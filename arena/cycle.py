"""The cycle state machine: planned, running, evaluating, then committed or rolled back.

State lives in the database, so a killed process resumes the open cycle instead of starting a new
one. Moving to the state a cycle is already in is a no-op, which keeps resumed steps idempotent.
"""

import sqlite3

from arena import db

TRANSITIONS: dict[str, frozenset[str]] = {
    "planned": frozenset({"running", "rolled_back"}),
    "running": frozenset({"evaluating", "rolled_back"}),
    "evaluating": frozenset({"committed", "rolled_back"}),
    "committed": frozenset(),
    "rolled_back": frozenset(),
}
FINISHED = ("committed", "rolled_back")


class IllegalTransition(RuntimeError):
    pass


def open_cycle(conn: sqlite3.Connection, run_id: str) -> int:
    """The run's unfinished cycle if there is one, otherwise a new planned cycle."""
    row = conn.execute(
        "SELECT id FROM cycles WHERE run_id = ? AND state NOT IN (?, ?) ORDER BY id DESC LIMIT 1",
        (run_id, *FINISHED),
    ).fetchone()
    if row is not None:
        return row[0]
    stamp = db.now()
    return conn.execute(
        "INSERT INTO cycles (run_id, state, created_at, updated_at) VALUES (?, 'planned', ?, ?)",
        (run_id, stamp, stamp),
    ).lastrowid


def state(conn: sqlite3.Connection, cycle_id: int) -> str:
    row = conn.execute("SELECT state FROM cycles WHERE id = ?", (cycle_id,)).fetchone()
    if row is None:
        raise KeyError(f"No cycle {cycle_id}.")
    return row[0]


def advance(conn: sqlite3.Connection, cycle_id: int, to: str) -> None:
    current = state(conn, cycle_id)
    if current == to:
        return
    if to not in TRANSITIONS[current]:
        raise IllegalTransition(f"Cycle {cycle_id} cannot go from {current} to {to}.")
    conn.execute(
        "UPDATE cycles SET state = ?, updated_at = ? WHERE id = ?", (to, db.now(), cycle_id)
    )


ORDER = ("planned", "running", "evaluating", "committed")


def reach(conn: sqlite3.Connection, cycle_id: int, to: str) -> None:
    """Move forward to `to` unless the cycle is already there or past it.

    A resumed cycle replays its earlier steps from stored outputs; this keeps those replays from
    trying to move the state backwards.
    """
    current = state(conn, cycle_id)
    if current == "rolled_back":
        raise IllegalTransition(f"Cycle {cycle_id} was rolled back and cannot continue.")
    while ORDER.index(current) < ORDER.index(to):
        current = ORDER[ORDER.index(current) + 1]
        advance(conn, cycle_id, current)
