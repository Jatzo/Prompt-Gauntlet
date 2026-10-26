import pytest

from arena import cycle

LEGAL = [
    ("planned", "running"),
    ("running", "evaluating"),
    ("evaluating", "committed"),
    ("planned", "rolled_back"),
    ("running", "rolled_back"),
    ("evaluating", "rolled_back"),
]
STATES = list(cycle.TRANSITIONS)
ILLEGAL = [(a, b) for a in STATES for b in STATES if a != b and (a, b) not in LEGAL]


def at(conn, state):
    cycle_id = cycle.open_cycle(conn, "run")
    conn.execute("UPDATE cycles SET state = ? WHERE id = ?", (state, cycle_id))
    return cycle_id


@pytest.mark.parametrize(("start", "end"), LEGAL)
def test_a_legal_transition_is_allowed(conn, start, end):
    cycle_id = at(conn, start)
    cycle.advance(conn, cycle_id, end)
    assert cycle.state(conn, cycle_id) == end


@pytest.mark.parametrize(("start", "end"), ILLEGAL)
def test_an_illegal_transition_raises(conn, start, end):
    cycle_id = at(conn, start)
    with pytest.raises(cycle.IllegalTransition):
        cycle.advance(conn, cycle_id, end)
    assert cycle.state(conn, cycle_id) == start


def test_an_unfinished_cycle_is_resumed_rather_than_replaced(conn):
    first = cycle.open_cycle(conn, "run")
    cycle.advance(conn, first, "running")
    assert cycle.open_cycle(conn, "run") == first


def test_a_finished_cycle_makes_way_for_a_new_one(conn):
    first = cycle.open_cycle(conn, "run")
    cycle.reach(conn, first, "committed")
    assert cycle.open_cycle(conn, "run") != first


def test_reach_never_moves_a_cycle_backwards(conn):
    cycle_id = at(conn, "evaluating")
    cycle.reach(conn, cycle_id, "running")
    assert cycle.state(conn, cycle_id) == "evaluating"


def test_a_rolled_back_cycle_cannot_continue(conn):
    cycle_id = at(conn, "rolled_back")
    with pytest.raises(cycle.IllegalTransition):
        cycle.reach(conn, cycle_id, "evaluating")
