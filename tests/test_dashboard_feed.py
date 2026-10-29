"""The dashboard's score, memory and operations panels: run-scoped reads of the agent database."""

import json

import pytest

from arena import cycle, dashboard_feed, db, llm
from arena.memory.memory import Memory
from arena.orchestrator import Orchestrator, phase1_mock_script
from arena.schemas import LessonProposal
from arena.server import open_read_only
from tests.conftest import STUB_REPORT, FakeJudge

HYPOTHESIS = "Spaced letters slip past every literal rule in the rota threads."
LESSON = "Literal rules miss spaced payloads."


def metric(value, half=0.05):
    return {"value": value, "ci_low": value - half, "ci_high": value + half, "clusters": 9}


def finished(conn, run_id="default", *, report=None, plan=None, state="committed"):
    memory = Memory(conn)
    with db.transaction(conn):
        cycle_id = cycle.open_cycle(conn, run_id)
        where = {"cycle_id": cycle_id, "step": "plan", "role": "ceo"}
        body = json.loads(phase1_mock_script()["plan"][0]) | {
            "focus": "obfuscation.spacing",
            "hypothesis_text": HYPOTHESIS,
        }
        plan_row = memory.record_episode(kind="plan", body=plan or body, **where)
        if report is not None:
            memory.record_episode(kind="judge_report", body=report, **where)
        conn.execute("UPDATE cycles SET state = ? WHERE id = ?", (state, cycle_id))
    return cycle_id, plan_row


@pytest.fixture
def ro(tmp_path, conn):
    reader = open_read_only(tmp_path / "arena.db")
    yield reader
    reader.close()


def report(**changes):
    return STUB_REPORT.model_dump(mode="json") | changes


def test_an_empty_database_has_no_run(ro):
    assert dashboard_feed.pick_run(ro, None) is None


def test_the_newest_cycles_run_is_the_default_and_a_known_run_can_be_asked_for(conn, ro):
    finished(conn, "first")
    finished(conn, "second")
    assert dashboard_feed.pick_run(ro, None) == "second"
    assert dashboard_feed.pick_run(ro, "first") == "first"
    assert dashboard_feed.pick_run(ro, "unknown") == "second"
    assert dashboard_feed.runs(ro) == ["second", "first"]


def test_scores_carry_each_committed_cycles_aggregates_for_one_run_only(conn, ro):
    good = report(
        asr=metric(0.3),
        utility=metric(0.9),
        decision="keep",
        reason_code="kept",
        per_category_fpr={"code": 0.02, "Bad-Key": 0.5},
    )
    finished(conn, "a", report=good)
    finished(conn, "a", report=report(decision="reject"), state="rolled_back")
    finished(conn, "b", report=report(asr=metric(0.9)))
    [point] = dashboard_feed.scores(ro, "a")["points"]
    assert point["asr"] == {"value": 0.3, "ci_low": 0.25, "ci_high": 0.35}
    assert point["decision"] == "keep" and point["reason"] == "kept"
    assert point["category_fpr"] == {"code": 0.02}
    assert point["tpr"] is None


def test_the_candidates_standing_comes_from_its_lineage_row(conn, ro):
    backend = llm.MockBackend(script=phase1_mock_script())
    Orchestrator(conn, backend=backend, judge=FakeJudge()).run_cycle()
    [point] = dashboard_feed.scores(ro, "default")["points"]
    assert point["standing"] == "kept_provisional"
    assert point["backend"] == "simulated"


def test_memory_shows_the_briefing_the_ceo_was_sent_and_the_plan(conn, ro):
    backend = llm.MockBackend(script=phase1_mock_script())
    Orchestrator(conn, backend=backend, judge=FakeJudge()).run_cycle()
    stored = Memory(conn).episode(1, "briefing")["text"]
    shown = dashboard_feed.memory(ro, "default")
    assert shown["briefing"] == {"cycle": 1, "text": stored}
    assert shown["plan"]["cycle"] == 1 and shown["plan"]["hypothesis"] == "Scripted plan 1."


def test_memory_lists_lessons_with_their_evidence_cycles_and_only_open_backlog(conn, ro):
    cycle_id, plan_row = finished(conn)
    with db.transaction(conn):
        memory = Memory(conn)
        memory.add_lesson(
            LessonProposal(
                text=LESSON,
                scope_tags=["obfuscation"],
                evidence_experiment_ids=[plan_row],
                confidence=0.6,
            ),
            cycle_id=cycle_id,
            step="postmortem",
            role="ceo",
        )
        memory.add_backlog_item("Try a homoglyph fold.", cycle_id=cycle_id, step="pm", role="ceo")
        done = memory.add_backlog_item("Old idea.", cycle_id=cycle_id, step="pm", role="ceo")
        conn.execute("UPDATE memory_backlog SET status = 'abandoned' WHERE id = ?", (done,))
    shown = dashboard_feed.memory(ro, "default")
    [lesson] = shown["lessons"]
    assert lesson["text"] == LESSON and lesson["evidence_cycles"] == [cycle_id]
    assert [item["text"] for item in shown["backlog"]] == ["Try a homoglyph fold."]


def test_ops_shows_control_anomalies_usage_and_notes(conn, ro):
    cycle_id, _ = finished(conn)
    with db.transaction(conn):
        db.raise_anomaly(conn, "plateau", {"message": "flat"}, cycle_id=cycle_id)
        conn.execute(
            "INSERT INTO usage (cycle_id, role, model_id, input_tokens, output_tokens, headroom,"
            " created_at) VALUES (?, 'ceo', 'm', 100, 20, 0.5, 't'), (?, 'ceo', 'm', 50, 5, 0.4,"
            " 't')",
            (cycle_id, cycle_id),
        )
        Memory(conn).add_operator_note("Look at code samples.")
    shown = dashboard_feed.ops(ro, "default")
    assert shown["control"] == {"state": "paused", "reason": ["anomaly", "plateau"]}
    assert [a["kind"] for a in shown["anomalies"]] == ["plateau"]
    assert shown["usage"] == [
        {"role": "ceo", "calls": 2, "input_tokens": 150, "output_tokens": 25, "headroom": 0.4}
    ]
    assert [note["text"] for note in shown["notes"]] == ["Look at code samples."]


def test_agent_text_reaches_the_memory_panel_only(conn, ro):
    cycle_id, plan_row = finished(conn, report=report(asr=metric(0.3)))
    with db.transaction(conn):
        Memory(conn).add_lesson(
            LessonProposal(
                text=LESSON,
                scope_tags=["obfuscation"],
                evidence_experiment_ids=[plan_row],
                confidence=0.6,
            ),
            cycle_id=cycle_id,
            step="postmortem",
            role="ceo",
        )
    for builder in (dashboard_feed.scores, dashboard_feed.ops):
        text = json.dumps(builder(ro, "default"))
        assert HYPOTHESIS not in text and LESSON not in text
    assert HYPOTHESIS in json.dumps(dashboard_feed.memory(ro, "default"))
