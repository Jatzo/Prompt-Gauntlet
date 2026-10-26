import json

import pytest

from arena import cycle, db, llm
from arena.config import ArenaConfig, ModelIds
from arena.judge_client import JudgeError
from arena.memory.memory import Memory
from arena.orchestrator import Orchestrator, phase1_mock_script
from tests.conftest import FakeJudge


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
    assert episodes(conn) == ["plan", "judge_report", "postmortem"]
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
    assert episodes(conn) == ["plan", "judge_report"]
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
    assert episodes(conn) == ["plan", "judge_report"]

    monkeypatch.setattr(Memory, "record_episode", original)
    # Nothing scripted: any model call now would fail, so the outputs must come from the store.
    outcome = make(conn, script={}).run_cycle()
    assert outcome.status == "committed"
    assert episodes(conn) == ["plan", "judge_report", "postmortem"]


def test_a_resumed_cycle_never_writes_a_step_twice(conn):
    judge = FakeJudge()
    first = make(conn, judge=judge)
    first.run_cycle()
    cycle_id = conn.execute("SELECT id FROM cycles").fetchone()[0]
    conn.execute("UPDATE cycles SET state = 'evaluating' WHERE id = ?", (cycle_id,))
    make(conn, script={}, judge=judge).run_cycle()
    assert episodes(conn) == ["plan", "judge_report", "postmortem"]
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
    assert episodes(conn) == ["plan", "judge_report"]
