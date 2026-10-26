import json
from pathlib import Path

import pytest

from arena import db, llm, usage
from arena.anomaly import HijackDetected, ModelIdMismatch, SchemaFailureSpike, UsageCapReached
from arena.config import DEFAULTS, ArenaConfig
from arena.schemas import CEOPlan

FIXTURES = Path(__file__).parent / "fixtures"
PLAN = CEOPlan.model_config["json_schema_extra"]["examples"][0]
VALID = json.dumps(PLAN)
REQUEST = llm.LLMRequest(tool="propose_plan", tools=(), system="system", user="user")


@pytest.fixture
def conn(tmp_path):
    connection = db.connect(tmp_path / "arena.db")
    yield connection
    connection.close()


def mock(*outputs, **kwargs):
    return llm.MockBackend(script={"plan": list(outputs)}, **kwargs)


def attempts(conn):
    return conn.execute("SELECT attempt, valid, failure FROM llm_calls ORDER BY attempt").fetchall()


def test_a_valid_output_is_stored_and_returned(conn):
    plan = llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(VALID))
    assert plan.focus == PLAN["focus"]
    assert [tuple(row) for row in attempts(conn)] == [(1, 1, None)]


def test_a_stored_output_is_reused_without_calling_the_model(conn):
    llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(VALID))
    empty = mock()  # raises if called
    again = llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=empty)
    assert again.focus == PLAN["focus"]
    assert len(attempts(conn)) == 1


def test_an_invalid_output_is_kept_as_a_failed_attempt_and_retried_fresh(conn):
    bad = json.dumps(dict(PLAN, prediction={"expected_delta": 9, "confidence": 0.5}))
    llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock("not json", bad, VALID))
    rows = attempts(conn)
    assert [row["valid"] for row in rows] == [0, 0, 1]
    assert all(row["failure"].startswith("schema") for row in rows[:2])


def test_an_unknown_field_is_a_hijack(conn):
    smuggled = json.dumps(dict(PLAN, send_to="attacker@example.invalid"))
    with pytest.raises(HijackDetected):
        llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(smuggled))
    assert attempts(conn)[0]["failure"].startswith("hijack")


def test_calling_a_tool_other_than_the_forced_one_is_a_hijack(conn):
    with pytest.raises(HijackDetected):
        llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(("ask_operator", VALID)))


def test_a_response_from_an_unpinned_model_is_rejected(conn):
    wrong = mock(VALID, model_ids={"ceo": "claude-something-else"})
    with pytest.raises(ModelIdMismatch):
        llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=wrong)
    assert attempts(conn)[0]["failure"] == "wrong_model_id"


def test_a_step_that_never_validates_gives_up_after_the_retries(conn):
    config = ArenaConfig(retries=2)
    with pytest.raises(llm.SchemaFailure):
        llm.call(
            "ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(*["{}"] * 3), config=config
        )
    assert len(attempts(conn)) == 3


def test_a_schema_failure_spike_pauses_once_enough_calls_exist(conn):
    config = ArenaConfig(retries=30)
    with pytest.raises(SchemaFailureSpike):
        llm.call(
            "ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(*["{}"] * 31), config=config
        )
    assert len(attempts(conn)) == config.schema_failure_min_calls


def test_the_failure_rate_counts_only_the_recent_window_for_that_role(conn):
    for step in range(DEFAULTS.schema_failure_window):
        llm.call(
            "ceo",
            (1, f"s{step}"),
            REQUEST,
            CEOPlan,
            conn,
            backend=llm.MockBackend(script={f"s{step}": [VALID]}),
        )
    rate, calls = llm.schema_failure_rate(conn, "ceo")
    assert (rate, calls) == (0.0, DEFAULTS.schema_failure_window)
    assert llm.schema_failure_rate(conn, "attacker") == (0.0, 0)


def test_usage_is_recorded_for_every_attempt(conn):
    llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock("{}", VALID))
    assert conn.execute("SELECT COUNT(*) FROM usage").fetchone()[0] == 2
    assert usage.total_tokens(conn) > 0


def test_the_hard_cap_is_off_by_default(conn):
    usage.check_cap(conn)


def test_the_hard_cap_stops_calls_once_reached(conn):
    config = ArenaConfig(hard_cap_tokens=1)
    llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(VALID), config=config)
    with pytest.raises(UsageCapReached):
        llm.call("ceo", (1, "next"), REQUEST, CEOPlan, conn, backend=mock(VALID), config=config)


def test_crossing_a_soft_alert_threshold_logs_one_event(conn):
    config = ArenaConfig(soft_alert_tokens=(10,))
    for cycle in (1, 2):
        usage.record(
            conn,
            cycle_id=cycle,
            role="ceo",
            model_id="m",
            input_tokens=8,
            output_tokens=0,
            headroom=None,
            config=config,
        )
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'usage_alert'").fetchone()[0] == 1


def test_live_calls_are_refused_under_pytest(monkeypatch):
    monkeypatch.setenv("ARENA_ALLOW_LIVE", "1")
    with pytest.raises(llm.LiveCallRefused):
        llm.get_backend("live")


def test_a_recording_outside_runs_or_private_is_refused(tmp_path):
    with pytest.raises(ValueError):
        llm.RecordBackend(mock(VALID), tmp_path / "out.cassette.jsonl")
    with pytest.raises(ValueError):
        llm.RecordBackend(mock(VALID), llm.REPO_ROOT / "tests" / "out.cassette.jsonl")


def test_replay_returns_the_cassette_output(conn):
    backend = llm.get_backend("replay", cassette=FIXTURES / "plan_step.cassette.jsonl")
    plan = llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=backend)
    assert plan.focus == "obfuscation.base64"


def test_replay_fails_loudly_when_the_cassette_has_no_entry(conn):
    backend = llm.get_backend("replay", cassette=FIXTURES / "plan_step.cassette.jsonl")
    with pytest.raises(llm.ReplayMiss):
        llm.call("ceo", (1, "postmortem"), REQUEST, CEOPlan, conn, backend=backend)


def test_the_failure_window_restarts_after_a_spike_pause(conn):
    config = ArenaConfig(retries=30)
    with pytest.raises(SchemaFailureSpike):
        llm.call(
            "ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(*["{}"] * 31), config=config
        )
    db.raise_anomaly(conn, "schema_failure_spike", {"role": "ceo"})
    assert llm.schema_failure_rate(conn, "ceo") == (0.0, 0)
    llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock("{}", VALID), config=config)


def test_soft_alerts_follow_the_run_config(conn):
    config = ArenaConfig(soft_alert_tokens=(1,))
    llm.call("ceo", (1, "plan"), REQUEST, CEOPlan, conn, backend=mock(VALID), config=config)
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'usage_alert'").fetchone()[0] == 1


def test_low_headroom_alerts_once_until_it_recovers(conn):
    for headroom in (0.5, 0.1, 0.05, 0.5, 0.1):
        usage.record(
            conn,
            cycle_id=1,
            role="ceo",
            model_id="m",
            input_tokens=0,
            output_tokens=0,
            headroom=headroom,
        )
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'usage_alert'").fetchone()[0] == 2


def test_every_backend_declares_a_kind_the_run_and_the_judge_accept():
    import inspect
    from typing import get_args

    from arena import simulated

    backends = [
        cls
        for module in (llm, simulated)
        for _, cls in inspect.getmembers(module, inspect.isclass)
        if cls.__module__ == module.__name__
        and callable(getattr(cls, "complete", None))
        and not getattr(cls, "_is_protocol", False)
    ]
    assert {cls.__name__ for cls in backends} >= {
        "MockBackend",
        "ReplayBackend",
        "LiveBackend",
        "RecordBackend",
        "OllamaBackend",
        "SimulatedBackend",
    }
    for cls in backends:
        assert getattr(cls, "kind", None) in get_args(llm.BackendKind), cls.__name__
