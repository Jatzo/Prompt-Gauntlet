"""The CEO's focus shortlist and the checks on its plans and post-mortems (Phase 3 step 10)."""

import json

import pytest

from arena import cycle, db, llm
from arena.config import DEFAULTS, ArenaConfig
from arena.memory import shortlist
from arena.memory.memory import Memory
from arena.orchestrator import Orchestrator, phase1_mock_script
from arena.schemas import CEOPlan, Directive, LessonProposal
from arena.target.world import ATTACKER_PLACEHOLDER
from arena.taxonomy import FALLBACK, RULE_TECHNIQUES, TECHNIQUES
from tests.conftest import STUB_REPORT, FakeJudge, numbered

HELD_OUT = DEFAULTS.held_out_techniques
CHANNEL_FALLBACKS = {FALLBACK[channel] for channel in ("email", "document", "tool_output")}


def verdict(technique, *, evaded=True, held_back=False):
    return {
        "technique": technique,
        "valid": True,
        "evaded": evaded,
        "held_back": held_back,
        "refused": False,
    }


def past_cycle(
    conn,
    focus="explore",
    *,
    kind=None,
    hypothesis=None,
    decision=None,
    verdicts=(),
    state="committed",
):
    """A finished cycle written straight to memory; returns (cycle id, plan episode id)."""
    memory = Memory(conn)
    with db.transaction(conn):
        cycle_id = cycle.open_cycle(conn, "default")
        where = {"cycle_id": cycle_id, "step": "plan", "role": "ceo"}
        plan = json.loads(phase1_mock_script()["plan"][0]) | {
            "focus": focus,
            "hypothesis_text": hypothesis or f"Past plan {cycle_id}.",
        }
        plan_row = memory.record_episode(kind="plan", body=plan, **where)
        if kind:
            body = {"entries": [[kind, focus]], "dropped_kind": None}
            memory.record_episode(kind="shortlist", body=body, **where)
        if verdicts:
            body = {"texts": ["x"] * len(verdicts), "bands": [], "verdicts": list(verdicts)}
            memory.record_episode(kind="attack_batch", body=body, **where)
        if decision:
            report = STUB_REPORT.model_dump(mode="json") | {"decision": decision}
            memory.record_episode(kind="judge_report", body=report, **where)
        conn.execute("UPDATE cycles SET state = ? WHERE id = ?", (state, cycle_id))
    return cycle_id, plan_row


def add_lesson(conn, evidence, tags, status="active"):
    with db.transaction(conn):
        memory = Memory(conn)
        lesson_id = memory.add_lesson(
            LessonProposal(
                text=f"A lesson about {' and '.join(tags)}.",
                scope_tags=list(tags),
                evidence_experiment_ids=[evidence],
                confidence=0.5,
            ),
            cycle_id=1,
            step="postmortem",
            role="ceo",
        )
        if status != "active":
            conn.execute("UPDATE memory_lessons SET status = ? WHERE id = ?", (status, lesson_id))
    return lesson_id


def build(conn, config=DEFAULTS):
    return shortlist.build(conn, "default", config)


def by_kind(foci):
    return {entry.kind: entry.focus for entry in foci.entries}


def test_a_new_run_lists_the_least_tested_technique_and_explore(conn):
    foci = build(conn)
    assert [entry.kind for entry in foci.entries] == ["least_tested", "explore"]
    assert foci.foci[-1] == shortlist.EXPLORE


@pytest.mark.parametrize("seed", range(12))
def test_a_held_out_technique_is_never_listed(conn, seed):
    _, plan_row = past_cycle(conn, verdicts=[verdict(t) for t in HELD_OUT * 5])
    add_lesson(conn, plan_row, ["persona"])
    foci = build(conn, ArenaConfig(seed=seed))
    assert not set(foci.foci) & set(HELD_OUT)
    assert by_kind(foci)["revisit"] == "persona.switch"


def test_the_least_tested_technique_is_the_one_this_run_focused_on_least(conn):
    candidates = [t for t in TECHNIQUES if t not in HELD_OUT]
    for technique in candidates:
        if technique != "tool.argument":
            past_cycle(conn, technique)
    # A rolled-back cycle taught nothing, so its focus does not count as tested.
    past_cycle(conn, "tool.argument", state="rolled_back")
    assert by_kind(build(conn))["least_tested"] == "tool.argument"


def test_the_largest_miss_counts_only_the_evasions_the_judge_showed(conn):
    shown = [verdict("override.direct")] * 2
    held_back = [verdict("obfuscation.spacing", held_back=True)] * 5
    caught = [verdict("delimiter.fake_end", evaded=False)] * 5
    past_cycle(conn, verdicts=shown + held_back + caught)
    entry = next(e for e in build(conn).entries if e.kind == "largest_miss")
    assert entry.focus == "override.direct"
    assert entry.reason == "2 evasions in recent batches"


def test_evasions_older_than_the_recent_window_do_not_count(conn):
    past_cycle(conn, verdicts=[verdict("obfuscation.spacing")] * 5)
    past_cycle(conn, verdicts=[verdict("override.direct")])
    config = ArenaConfig(briefing_recent_experiments=1)
    assert by_kind(build(conn, config))["largest_miss"] == "override.direct"


def test_the_revisit_follows_the_oldest_active_lesson(conn):
    _, plan_row = past_cycle(conn)
    add_lesson(conn, plan_row, ["delimiter"], status="disputed")
    add_lesson(conn, plan_row, ["tool"])
    add_lesson(conn, plan_row, ["obfuscation"])
    entry = next(e for e in build(conn).entries if e.kind == "revisit")
    assert entry.focus == "tool.argument"
    assert "lesson 2" in entry.reason


def test_no_technique_is_listed_twice(conn):
    least = build(conn).foci[0]
    _, plan_row = past_cycle(conn, verdicts=[verdict(least)] * 3)
    add_lesson(conn, plan_row, [least])
    foci = build(conn)
    assert len(set(foci.foci)) == len(foci.foci)


def test_the_same_seed_gives_the_same_list_and_ties_follow_the_seed(conn):
    assert build(conn) == build(conn)
    firsts = {build(conn, ArenaConfig(seed=seed)).foci[0] for seed in range(12)}
    assert len(firsts) > 1


def test_the_plateau_switch_drops_the_focus_type_chosen_last_until_a_keep(conn):
    config = ArenaConfig(plateau_switch_n=2)
    past_cycle(conn, kind="explore", decision="reject")
    least = build(conn, config).foci[0]
    past_cycle(conn, least, kind="least_tested", decision="reject")
    switched = build(conn, config)
    assert switched.dropped_kind == "least_tested"
    assert "least_tested" not in by_kind(switched)
    assert "(least_tested) is off the list" in switched.text(config)
    past_cycle(conn, kind="explore", decision="keep")
    assert build(conn, config).dropped_kind is None


def run_once(conn, script, *, judge=None, config=DEFAULTS, backend_class=llm.MockBackend):
    backend = backend_class(script=script)
    return Orchestrator(
        conn, backend=backend, judge=judge or FakeJudge(), config=config
    ).run_cycle()


def plan_attempts(conn, step="plan"):
    rows = conn.execute(
        "SELECT valid, failure FROM llm_calls WHERE step = ? ORDER BY cycle_id, attempt", (step,)
    )
    return [tuple(row) for row in rows]


class Spy(llm.MockBackend):
    prompts: list[str] = []

    def complete(self, *, role, model_id, step_key, request):
        Spy.prompts.append(request.user)
        return super().complete(role=role, model_id=model_id, step_key=step_key, request=request)


def with_plans(*changes):
    script = phase1_mock_script()
    plan = json.loads(script["plan"][0])
    script["plan"] = [json.dumps(plan | change) for change in changes]
    return script


def test_a_focus_off_the_shortlist_is_asked_again_with_the_reason(conn):
    Spy.prompts = []
    script = with_plans({"focus": "obfuscation.base64"}, {"hypothesis_text": "A second idea."})
    assert run_once(conn, script, backend_class=Spy).status == "committed"
    [(refused, failure), (accepted, _)] = plan_attempts(conn)
    assert (refused, accepted) == (0, 1)
    assert "'obfuscation.base64' is not on the shortlist" in failure
    first, second = Spy.prompts[:2]
    assert "## Focus shortlist (pick one)" in first and "refused" not in first
    assert second.endswith(f"Your last output was refused: {failure.removeprefix('schema: ')}.")


def test_a_repeated_hypothesis_is_asked_again(conn):
    earlier = "Decoding base64 before the rules layer catches encoded overrides."
    past_cycle(conn, hypothesis=earlier)
    script = with_plans(
        {"hypothesis_text": earlier.replace("encoded", "the encoded")},
        {"hypothesis_text": "Spaced letters slip past every literal rule."},
    )
    assert run_once(conn, script).status == "committed"
    [(_, failure), _] = plan_attempts(conn)
    assert "nearly repeats the one in cycle 1" in failure


def test_a_plan_refused_on_every_attempt_rolls_the_cycle_back(conn):
    attempts = DEFAULTS.retries + 1
    script = with_plans(*[{"focus": "tool.argument.nope"}] * attempts)
    assert run_once(conn, script).status == "rolled_back"
    assert len(plan_attempts(conn)) == attempts


def test_refused_plans_count_towards_the_schema_failure_pause(conn):
    config = ArenaConfig(schema_failure_min_calls=2)
    script = with_plans(*[{"focus": "tool.argument.nope"}] * 5)
    outcome = run_once(conn, script, config=config)
    assert outcome.status == "paused"
    assert "schema_failure_spike" in outcome.detail


def test_a_post_mortem_must_acknowledge_each_new_operator_note(conn):
    Spy.prompts = []
    with db.transaction(conn):
        note = Memory(conn).add_operator_note("Look at the code category first.")
    script = phase1_mock_script()
    postmortem = json.loads(script["postmortem"][0])
    script["postmortem"] = [
        json.dumps(postmortem),
        json.dumps(postmortem | {"operator_notes_acknowledged": [note]}),
    ]
    assert run_once(conn, script, backend_class=Spy).status == "committed"
    [(_, failure), (accepted, _)] = plan_attempts(conn, "postmortem")
    assert failure == f"schema: operator notes [{note}] are not acknowledged" and accepted == 1
    assert f"Operator notes to acknowledge: {note}." in Spy.prompts[-1]
    # Acknowledged once, the note asks for nothing more.
    Spy.prompts = []
    assert run_once(conn, numbered(phase1_mock_script(), conn), backend_class=Spy).status == (
        "committed"
    )
    assert "Operator notes to acknowledge: none." in Spy.prompts[-1]


@pytest.mark.parametrize(("cite", "cites_lesson"), [(True, True), (False, False)])
def test_the_briefing_usage_check_logs_whether_the_plan_cites_a_lesson_it_was_shown(
    conn, cite, cites_lesson
):
    _, plan_row = past_cycle(conn)
    lesson_id = add_lesson(conn, plan_row, ["obfuscation"])
    script = with_plans({"cites_lesson_ids": [lesson_id] if cite else []})
    assert run_once(conn, numbered(script, conn)).status == "committed"
    [detail] = conn.execute("SELECT detail FROM events WHERE kind = 'briefing_usage'").fetchall()
    usage = json.loads(detail[0])
    assert usage["cites_lesson"] is cites_lesson
    assert usage["shown"] == [lesson_id]


def test_the_plateau_pauses_the_run_and_resuming_gives_it_another_m_cycles(conn):
    config = ArenaConfig(plateau_pause_m=2)
    backend = llm.MockBackend(script=phase1_mock_script(4))
    orchestrator = Orchestrator(conn, backend=backend, judge=FakeJudge(keep=False), config=config)
    assert [orchestrator.run_cycle().status for _ in range(2)] == ["committed", "committed"]
    paused = orchestrator.run_cycle()
    assert paused.status == "paused" and "plateau" in paused.detail
    [detail] = conn.execute("SELECT detail FROM events WHERE kind = 'plateau'").fetchall()
    report = json.loads(detail[0])
    assert report["committed_cycles"] == 2 and report["keeps"] == 0
    assert report["cycles_since_last_keep"] == 2
    assert sum(report["foci_tried"].values()) == 2
    with db.transaction(conn):
        db.set_control(conn, "running", "operator: resume")
    assert orchestrator.run_cycle().status == "committed"


def explore_plan(hypothesis="Try a channel nobody has used."):
    plan = json.loads(phase1_mock_script()["plan"][0])
    return CEOPlan.model_validate(plan | {"focus": "explore", "hypothesis_text": hypothesis})


def test_the_explore_directive_names_no_held_out_or_fallback_technique(conn):
    orchestrator = Orchestrator(conn, backend=llm.MockBackend(script={}), judge=FakeJudge())
    directive = orchestrator._directive(explore_plan("x" * 2000))
    Directive.model_validate(directive.model_dump())
    text = directive.hypothesis_text
    assert text.startswith("x") and len(text) <= 2000
    for technique in RULE_TECHNIQUES:
        assert (technique in text) is (technique not in HELD_OUT)
    assert not any(fallback in text for fallback in CHANNEL_FALLBACKS)
    assert directive.constraints == [
        f"The goal is one of the toy app's own actions, with {ATTACKER_PLACEHOLDER} as the only"
        " recipient."
    ]


def test_a_technique_focus_gets_the_hypothesis_as_written(conn):
    orchestrator = Orchestrator(conn, backend=llm.MockBackend(script={}), judge=FakeJudge())
    plan = explore_plan().model_copy(update={"focus": "override.direct"})
    directive = orchestrator._directive(plan)
    assert directive.hypothesis_text == plan.hypothesis_text
    assert directive.constraints == []


def test_a_long_mock_run_follows_the_plateau_switch_without_a_refusal(conn):
    config = ArenaConfig(plateau_switch_n=2, plateau_pause_m=20)
    backend = llm.MockBackend(script=phase1_mock_script(8))
    orchestrator = Orchestrator(conn, backend=backend, judge=FakeJudge(keep=False), config=config)
    assert [orchestrator.run_cycle().status for _ in range(8)] == ["committed"] * 8
    assert all(valid for valid, _ in plan_attempts(conn))
