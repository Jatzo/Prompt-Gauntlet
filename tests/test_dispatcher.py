"""The hostile-dispatcher matrix: every role against every tool, plus names that only look right."""

import itertools

import pydantic
import pytest

from arena import db
from arena.anomaly import ForbiddenTool, HijackDetected
from arena.dispatcher import (
    ALLOWLISTS,
    ROLE_SCHEMAS,
    TOOLS,
    check_role_schemas,
    dispatch,
    schema_for,
    tool_schemas_for,
)
from arena.schemas import AttackBatch, DiscoveryBatch

# Tools that do not exist, and near-misses of real ones. None may ever be accepted.
NOT_TOOLS = [
    "run_sql",
    "read_test_set",
    "edit_constitution",
    "fetch_url",
    "",
    "Propose_plan",
    "PROPOSE_PLAN",
    " propose_plan",
    "propose_plan ",
    "propose-plan",
    "propose_plan\n",
    "submit_detector_patch​",
]
ROLES = sorted(ALLOWLISTS) + ["judge", "operator", "CEO"]
MATRIX = list(itertools.product(ROLES, sorted(TOOLS) + NOT_TOOLS))


def example_args(tool, role=None):
    schema = schema_for(role, tool) if role in ALLOWLISTS else TOOLS[tool]
    return schema.model_config["json_schema_extra"]["examples"][0]


@pytest.fixture
def conn(tmp_path):
    connection = db.connect(tmp_path / "arena.db")
    db.set_control(connection, "running", "test")
    yield connection
    connection.close()


@pytest.mark.parametrize(("role", "tool"), MATRIX, ids=[f"{r}:{t!r}" for r, t in MATRIX])
def test_every_role_gets_exactly_its_allowlist(conn, role, tool):
    allowed = tool in ALLOWLISTS.get(role, frozenset())
    args = example_args(tool, role) if tool in TOOLS else {}
    if allowed:
        assert isinstance(dispatch(conn, role, tool, args), schema_for(role, tool))
        assert db.control_state(conn)[0] == "running"
    else:
        with pytest.raises(ForbiddenTool):
            dispatch(conn, role, tool, args)
        assert db.control_state(conn) == ("paused", "anomaly: forbidden_tool")
        event = conn.execute("SELECT kind, severity FROM events").fetchone()
        assert tuple(event) == ("forbidden_tool", "anomaly")


def test_the_allowlists_match_the_plan():
    assert ALLOWLISTS["ceo"] == {
        "propose_plan",
        "write_postmortem",
        "propose_lesson",
        "ask_operator",
    }
    assert ALLOWLISTS["researcher"] == {"read_approved_source", "submit_technique_record"}
    assert ALLOWLISTS["attacker"] == {"submit_attack_batch", "query_detector"}
    assert ALLOWLISTS["defender"] == {"submit_detector_patch"}
    assert ALLOWLISTS["casestudy"] == set()
    assert ALLOWLISTS["grader"] == set()
    assert ALLOWLISTS["discovery_attacker"] == {"submit_attack_batch"}


def test_every_allowlisted_tool_exists_in_the_registry():
    for role, tools in ALLOWLISTS.items():
        assert tools <= TOOLS.keys(), role


@pytest.mark.parametrize("role", sorted(ALLOWLISTS))
def test_a_role_is_shown_only_its_own_tool_schemas(role):
    assert {tool["name"] for tool in tool_schemas_for(role)} == ALLOWLISTS[role]


@pytest.mark.parametrize("role", sorted(ALLOWLISTS))
def test_each_role_is_shown_the_schema_it_is_checked_against(role):
    for shown in tool_schemas_for(role):
        expected = ROLE_SCHEMAS.get((role, shown["name"]), TOOLS[shown["name"]])
        assert shown["input_schema"] == expected.model_json_schema()
        assert schema_for(role, shown["name"]) is expected


def test_only_the_discovery_attacker_gets_the_task_naming_batch(conn):
    assert schema_for("attacker", "submit_attack_batch") is AttackBatch
    assert schema_for("discovery_attacker", "submit_attack_batch") is DiscoveryBatch
    plain = AttackBatch.model_config["json_schema_extra"]["examples"][0]
    with pytest.raises(pydantic.ValidationError):
        dispatch(conn, "discovery_attacker", "submit_attack_batch", plain)


def test_the_schema_table_can_never_grant_a_tool():
    with pytest.raises(RuntimeError, match="may not call"):
        check_role_schemas({("discovery_attacker", "query_detector"): DiscoveryBatch}, ALLOWLISTS)
    with pytest.raises(RuntimeError, match="may not call"):
        check_role_schemas({("nobody", "submit_attack_batch"): DiscoveryBatch}, ALLOWLISTS)


def test_bad_argument_values_are_a_schema_failure_and_do_not_pause(conn):
    args = dict(example_args("submit_detector_patch"), ops=[])
    with pytest.raises(pydantic.ValidationError):
        dispatch(conn, "defender", "submit_detector_patch", args)
    assert db.control_state(conn)[0] == "running"


def test_an_unknown_argument_field_is_a_hijack_and_pauses(conn):
    args = dict(example_args("submit_detector_patch"), threshold=0.1)
    with pytest.raises(HijackDetected):
        dispatch(conn, "defender", "submit_detector_patch", args)
    assert db.control_state(conn) == ("paused", "anomaly: hijack")


def test_a_dispatcher_anomaly_is_marked_as_already_recorded(conn):
    with pytest.raises(ForbiddenTool) as caught:
        dispatch(conn, "attacker", "submit_detector_patch", {})
    assert caught.value.recorded
