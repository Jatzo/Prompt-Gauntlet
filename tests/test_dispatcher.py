"""The hostile-dispatcher matrix: every role against every tool, plus names that only look right."""

import itertools

import pydantic
import pytest

from arena import db
from arena.anomaly import ForbiddenTool, HijackDetected
from arena.dispatcher import ALLOWLISTS, TOOLS, dispatch, tool_schemas_for

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


def example_args(tool):
    return TOOLS[tool].model_config["json_schema_extra"]["examples"][0]


@pytest.fixture
def conn(tmp_path):
    connection = db.connect(tmp_path / "arena.db")
    db.set_control(connection, "running", "test")
    yield connection
    connection.close()


@pytest.mark.parametrize(("role", "tool"), MATRIX, ids=[f"{r}:{t!r}" for r, t in MATRIX])
def test_every_role_gets_exactly_its_allowlist(conn, role, tool):
    allowed = tool in ALLOWLISTS.get(role, frozenset())
    args = example_args(tool) if tool in TOOLS else {}
    if allowed:
        assert isinstance(dispatch(conn, role, tool, args), TOOLS[tool])
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


def test_every_allowlisted_tool_exists_in_the_registry():
    for role, tools in ALLOWLISTS.items():
        assert tools <= TOOLS.keys(), role


@pytest.mark.parametrize("role", sorted(ALLOWLISTS))
def test_a_role_is_shown_only_its_own_tool_schemas(role):
    assert {tool["name"] for tool in tool_schemas_for(role)} == ALLOWLISTS[role]


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
