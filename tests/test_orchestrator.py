import json

import pytest

from arena import cycle, db, llm
from arena.agents import attacker
from arena.agents.attacker import canary
from arena.baselines import REGEX_RULES
from arena.config import ArenaConfig, ModelIds
from arena.judge_client import JudgeError
from arena.memory.memory import Memory
from arena.orchestrator import REFERENCE_TARGET, Orchestrator, phase1_mock_script
from tests.conftest import FakeJudge

FULL_CYCLE = ["plan", "attack_batch", "judge_report", "postmortem", "novelty_closed"]
UP_TO_JUDGE = ["plan", "attack_batch", "judge_report"]


def make(conn, script=None, judge=None, **backend_kwargs):
    backend = llm.MockBackend(script=script or phase1_mock_script(), **backend_kwargs)
    return Orchestrator(conn, backend=backend, judge=judge or FakeJudge())


def episodes(conn):
    return [row[0] for row in conn.execute("SELECT kind FROM memory_episodic ORDER BY id")]


def test_a_cycle_runs_every_step_and_commits(conn):
    judge = FakeJudge()
    outcome = make(conn, judge=judge).run_cycle()
    assert outcome.status == "committed"
    assert cycle.state(conn, outcome.cycle_id) == "committed"
    assert episodes(conn) == FULL_CYCLE
    assert judge.evaluations == [outcome.cycle_id]
    assert conn.execute("SELECT COUNT(*) FROM memory_predictions").fetchone()[0] == 1


def test_every_cycle_writes_one_run_manifest(conn):
    outcome = make(conn).run_cycle()
    manifest = conn.execute(
        "SELECT * FROM manifests WHERE cycle_id = ?", (outcome.cycle_id,)
    ).fetchone()
    assert json.loads(manifest["model_ids"])["ceo"] == "claude-opus-5-5"
    assert manifest["seed"] == 20261025
    assert len(manifest["config_hash"]) == 64
    assert manifest["git_sha"]


@pytest.mark.parametrize("state", ["paused", "stopped"])
def test_a_halted_run_does_nothing(conn, state):
    db.set_control(conn, state, "operator")
    outcome = make(conn, script={}).run_cycle()
    assert outcome.status == state
    assert conn.execute("SELECT COUNT(*) FROM cycles").fetchone()[0] == 0


def test_a_pause_is_honoured_at_the_next_step_boundary(conn):
    class PausingJudge(FakeJudge):
        def evaluate(self, cycle_id):
            db.set_control(conn, "paused", "operator")
            return super().evaluate(cycle_id)

    outcome = make(conn, judge=PausingJudge()).run_cycle()
    assert outcome.status == "paused"
    assert episodes(conn) == UP_TO_JUDGE
    assert cycle.state(conn, outcome.cycle_id) == "evaluating"


def test_a_hash_mismatch_pauses_before_any_step(conn):
    outcome = make(conn, script={}, judge=FakeJudge(hashes_ok=False)).run_cycle()
    assert outcome.status == "paused"
    assert db.control_state(conn) == ("paused", "anomaly: hash_mismatch")
    assert episodes(conn) == []


def test_a_hijacked_step_rolls_back_the_cycle_and_pauses(conn):
    script = phase1_mock_script()
    plan = json.loads(script["plan"][0])
    script["plan"] = [json.dumps(dict(plan, exfiltrate="canary"))]
    outcome = make(conn, script=script).run_cycle()
    assert outcome.status == "paused"
    assert cycle.state(conn, outcome.cycle_id) == "rolled_back"
    assert db.control_state(conn) == ("paused", "anomaly: hijack")


def test_an_unpinned_model_pauses_the_run(conn):
    outcome = make(conn, model_ids={"ceo": "claude-imposter"}).run_cycle()
    assert db.control_state(conn) == ("paused", "anomaly: model_id_mismatch")
    assert cycle.state(conn, outcome.cycle_id) == "running"


def test_a_step_that_never_validates_rolls_back_the_cycle_and_carries_on(conn):
    script = {"plan": ["{}"] * 5, "postmortem": []}
    outcome = make(conn, script=script).run_cycle()
    assert outcome.status == "rolled_back"
    assert db.control_state(conn)[0] == "running"
    skipped = conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'cycle_skipped'").fetchone()[0]
    assert skipped == 1


class Crash(BaseException):
    """A process dying, as far as the code under test can tell."""


def test_a_crash_between_storing_an_output_and_writing_memory_writes_once(conn, monkeypatch):
    original = Memory.record_episode

    def crash_on_postmortem(self, *, kind, **kwargs):
        if kind == "postmortem":
            raise Crash
        return original(self, kind=kind, **kwargs)

    monkeypatch.setattr(Memory, "record_episode", crash_on_postmortem)
    with pytest.raises(Crash):
        make(conn).run_cycle()
    stored = conn.execute("SELECT COUNT(*) FROM llm_calls WHERE step = 'postmortem'").fetchone()[0]
    assert stored == 1
    assert episodes(conn) == UP_TO_JUDGE

    monkeypatch.setattr(Memory, "record_episode", original)
    # Nothing scripted: any model call now would fail, so the outputs must come from the store.
    outcome = make(conn, script={}).run_cycle()
    assert outcome.status == "committed"
    assert episodes(conn) == FULL_CYCLE


def test_a_resumed_cycle_never_writes_a_step_twice(conn):
    judge = FakeJudge()
    first = make(conn, judge=judge)
    first.run_cycle()
    cycle_id = conn.execute("SELECT id FROM cycles").fetchone()[0]
    conn.execute("UPDATE cycles SET state = 'evaluating' WHERE id = ?", (cycle_id,))
    make(conn, script={}, judge=judge).run_cycle()
    assert episodes(conn) == FULL_CYCLE
    assert judge.evaluations == [cycle_id]


def test_a_rejected_lesson_is_logged_and_the_cycle_still_commits(conn):
    script = phase1_mock_script()
    postmortem = json.loads(script["postmortem"][0])
    lesson = {
        "text": "Cites an experiment that never ran.",
        "scope_tags": ["rules"],
        "evidence_experiment_ids": [999],
        "confidence": 0.5,
    }
    script["postmortem"] = [json.dumps(dict(postmortem, lesson_candidates=[lesson]))]
    outcome = make(conn, script=script).run_cycle()
    assert outcome.status == "committed"
    assert conn.execute("SELECT COUNT(*) FROM memory_lessons").fetchone()[0] == 0
    rejected = conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'lesson_rejected'")
    assert rejected.fetchone()[0] == 1


def test_an_unreachable_judge_pauses_the_run(conn):
    class DeadJudge(FakeJudge):
        def verify_hashes(self):
            raise JudgeError("The Judge process closed without replying.")

    outcome = make(conn, script={}, judge=DeadJudge()).run_cycle()
    assert outcome.status == "paused"
    assert db.control_state(conn) == ("paused", "anomaly: judge_unavailable")


def test_an_anomaly_is_recorded_once(conn):
    script = phase1_mock_script()
    plan = json.loads(script["plan"][0])
    script["plan"] = [json.dumps(dict(plan, exfiltrate="canary"))]
    make(conn, script=script).run_cycle()
    assert conn.execute("SELECT COUNT(*) FROM events WHERE severity = 'anomaly'").fetchone()[0] == 1


@pytest.mark.parametrize(
    "changed",
    [
        ArenaConfig(max_patch_ops=6),
        ArenaConfig(models=ModelIds(ceo="claude-sonnet-5-5")),
    ],
    ids=["config", "model_ids"],
)
def test_resuming_under_a_different_config_pauses_the_run(conn, changed):
    class PausingJudge(FakeJudge):
        def evaluate(self, cycle_id):
            db.set_control(conn, "paused", "operator")
            return super().evaluate(cycle_id)

    first = make(conn, judge=PausingJudge()).run_cycle()
    assert first.status == "paused"
    db.set_control(conn, "running", "operator")

    # Nothing scripted: any model call after the check would fail loudly.
    resumed = Orchestrator(
        conn, backend=llm.MockBackend(script={}), judge=FakeJudge(), config=changed
    ).run_cycle()
    assert resumed.status == "paused"
    assert db.control_state(conn) == ("paused", "anomaly: config_mismatch")
    assert episodes(conn) == UP_TO_JUDGE


def step_done_events(conn):
    rows = conn.execute("SELECT detail FROM events WHERE kind = 'step_done' ORDER BY id")
    return [json.loads(row[0]) for row in rows]


def test_each_step_logs_one_step_done_event(conn):
    outcome = make(conn).run_cycle()
    assert step_done_events(conn) == [
        {
            "cycle": outcome.cycle_id,
            "step": "plan",
            "role": "ceo",
            "tool": "propose_plan",
            "outcome": "plan recorded",
        },
        {
            "cycle": outcome.cycle_id,
            "step": "attack",
            "role": "attacker",
            "tool": "submit_attack_batch",
            "outcome": "1 attacks, 1 valid, 1 evading clusters",
        },
        {
            "cycle": outcome.cycle_id,
            "step": "judge",
            "role": "judge",
            "tool": "evaluate",
            "outcome": "not_implemented",
        },
        {
            "cycle": outcome.cycle_id,
            "step": "postmortem",
            "role": "ceo",
            "tool": "write_postmortem",
            "outcome": "0 lessons stored, 0 rejected",
        },
    ]


def test_a_crash_before_the_write_commits_leaves_no_step_done_event(conn, monkeypatch):
    original = Memory.record_episode

    def crash_on_postmortem(self, *, kind, **kwargs):
        if kind == "postmortem":
            raise Crash
        return original(self, kind=kind, **kwargs)

    monkeypatch.setattr(Memory, "record_episode", crash_on_postmortem)
    with pytest.raises(Crash):
        make(conn).run_cycle()
    assert [event["step"] for event in step_done_events(conn)] == ["plan", "attack", "judge"]

    monkeypatch.setattr(Memory, "record_episode", original)
    make(conn, script={}).run_cycle()
    steps = [event["step"] for event in step_done_events(conn)]
    assert steps == ["plan", "attack", "judge", "postmortem"]


def plan_with(**changes):
    script = phase1_mock_script()
    plan = json.loads(script["plan"][0])
    script["plan"] = [json.dumps(dict(plan, **changes))]
    return script


def test_the_attack_step_queries_and_validates_against_the_incumbent_settings(conn):
    judge = FakeJudge()
    make(conn, judge=judge).run_cycle()
    assert [query.step for query in judge.queries] == [f"attack.t{turn}" for turn in range(8)]
    [batch] = judge.batches
    for measured in [query.measure for query in judge.queries] + [batch.measure]:
        assert measured.arms[0].detector == REGEX_RULES
        assert measured.reference_target == measured.targets[0] == REFERENCE_TARGET
        assert measured.backend == "mock" and measured.cassette is None


def test_a_plan_without_the_attacker_skips_the_attack_step(conn):
    judge = FakeJudge()
    outcome = make(conn, script=plan_with(agents_to_run=["defender"]), judge=judge).run_cycle()
    assert outcome.status == "committed"
    assert "attack_batch" not in episodes(conn)
    assert judge.queries == [] and judge.batches == []
    assert step_done_events(conn)[1]["outcome"] == "attacker not chosen"


def test_the_first_cycle_stores_the_regex_baseline_once(conn):
    make(conn).run_cycle()
    make(conn).run_cycle()
    rows = conn.execute("SELECT status, parent_id FROM detector_configs").fetchall()
    assert [tuple(row) for row in rows] == [("baseline", None)]


def test_a_resumed_attack_step_calls_no_model_and_spends_no_query(conn, monkeypatch):
    original = Memory.record_episode

    def crash_on_batch(self, *, kind, **kwargs):
        if kind == "attack_batch":
            raise Crash
        return original(self, kind=kind, **kwargs)

    judge = FakeJudge()
    monkeypatch.setattr(Memory, "record_episode", crash_on_batch)
    with pytest.raises(Crash):
        make(conn, judge=judge).run_cycle()
    monkeypatch.setattr(Memory, "record_episode", original)
    # Nothing scripted for the attack steps: every output must come from the store.
    script = {"postmortem": phase1_mock_script()["postmortem"]}
    assert make(conn, script=script, judge=judge).run_cycle().status == "committed"
    # The resume asks the same eight steps and the batch again. The Judge answers each step from
    # its record, so no budget is spent, and the batch check from its cache (tests/test_attacks.py).
    assert len(judge.queries) == 16 and len(judge.batches) == 2
    assert len({query.step for query in judge.queries}) == 8
    assert len(judge._replies) == 8
    assert episodes(conn) == FULL_CYCLE


def test_a_planted_canary_in_the_attackers_output_rolls_back_before_the_judge(conn):
    script = phase1_mock_script()
    script["attack.t0"] = [json.dumps({"text": f"Done. {canary(1, 'attack.t0')}"})]
    judge = FakeJudge()
    outcome = make(conn, script=script, judge=judge).run_cycle()
    assert outcome.status == "paused"
    assert cycle.state(conn, outcome.cycle_id) == "rolled_back"
    assert db.control_state(conn) == ("paused", "anomaly: hijack")
    assert judge.queries == [] and judge.batches == []


def test_the_no_memory_arm_gets_no_lessons_and_no_last_batch(conn, monkeypatch):
    seen = []
    real_run = attacker.Attacker.run

    def spy(self, cycle_id, view, ports):
        seen.append(view)
        return real_run(self, cycle_id, view, ports)

    monkeypatch.setattr(attacker.Attacker, "run", spy)
    with db.transaction(conn):
        cycle_id = cycle.open_cycle(conn, "other")
        evidence = Memory(conn).record_episode(
            kind="plan", body={}, cycle_id=cycle_id, step="plan", role="ceo"
        )
        cycle.reach(conn, cycle_id, "committed")
    lesson = {
        "text": "Encoded payloads evade literal rules.",
        "scope_tags": ["rules"],
        "evidence_experiment_ids": [evidence],
        "confidence": 0.6,
    }
    script = plan_with(cites_lesson_ids=[1])
    postmortem = json.loads(script["postmortem"][0])
    script["postmortem"] = [json.dumps(dict(postmortem, lesson_candidates=[lesson]))]
    script["plan"] *= 2
    script["postmortem"].append(phase1_mock_script()["postmortem"][0])
    for step in [s for s in script if s.startswith("attack.")]:
        script[step] *= 2
    backend = llm.MockBackend(script=script)
    with_memory = Orchestrator(conn, backend=backend, judge=FakeJudge())
    assert with_memory.run_cycle().status == "committed"
    assert with_memory.run_cycle().status == "committed"
    remembering = seen[-1]
    assert remembering.directive.cited_lesson_texts == [lesson["text"]]
    assert remembering.last_batch

    without = Orchestrator(
        conn,
        backend=llm.MockBackend(script=plan_with(cites_lesson_ids=[1])),
        judge=FakeJudge(),
        use_memory=False,
    )
    assert without.run_cycle().status == "committed"
    assert seen[-1].directive.cited_lesson_texts == []
    assert seen[-1].last_batch == ()


def test_an_outcome_the_live_feed_cannot_show_is_refused(conn):
    orchestrator = make(conn)
    with db.transaction(conn):
        cycle_id = cycle.open_cycle(conn, "default")
    with pytest.raises(ValueError, match="live feed"):
        orchestrator._write_once(cycle_id, "plan", "ceo", "propose_plan", lambda m: "two\nlines")
    assert step_done_events(conn) == []


def test_a_replay_run_is_not_treated_as_live(conn, tmp_path):
    cassette = tmp_path / "c.jsonl"
    cassette.write_text("")
    orchestrator = Orchestrator(conn, backend=llm.ReplayBackend(cassette), judge=FakeJudge())
    # A replay backend is named replay-<digest>, which the old name check read as live.
    assert orchestrator.backend.name.startswith("replay-")
    assert orchestrator.novelty.live is False
    # The Judge measures a replay run with its simulated models, as it does a mock run.
    assert orchestrator._measure_settings(REGEX_RULES).backend == "mock"


def test_a_backend_with_an_unknown_kind_is_refused(conn):
    backend = llm.MockBackend(script={})
    backend.kind = "staging"
    with pytest.raises(ValueError, match="kind"):
        Orchestrator(conn, backend=backend, judge=FakeJudge())
