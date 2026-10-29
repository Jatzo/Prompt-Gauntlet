"""The dashboard's only writes: the control flag and operator notes (PLAN section 15, panel 4).

Kept apart from the read-only server code so the write path stays this small. Each write opens the
existing database read-write through plain `sqlite3`, never through `arena.db.connect`, which would
create a missing file, migrate a schema beside a live run and run an integrity check on every call.
A missing file or another schema version is refused, and a run holding the write lock past the
timeout gets a busy answer instead of a wait.

"Start" sets the flag that lets the next `run` go ahead. Nothing here launches a process.

Notes have no run of their own: every briefing in the database shows them. So a note is refused
while a run is mid-cycle in a database that holds more than one run, where it could reach an
ablation arm partway through. A note is permanent and never cut from a briefing, which is why its
length is capped here.
"""

import sqlite3
from pathlib import Path

from arena import db
from arena.cycle import FINISHED
from arena.memory.memory import Memory

NOTE_CHARS = 1000
LOCK_SECONDS = 5.0


class Refused(Exception):
    """A write the dashboard may not make now. `status` is the HTTP status to answer with."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def notes_blocked(conn: sqlite3.Connection) -> bool:
    """True while a run is mid-cycle in a database that holds more than one run."""
    if conn.execute("SELECT COUNT(DISTINCT run_id) FROM cycles").fetchone()[0] < 2:
        return False
    placeholders = ",".join("?" * len(FINISHED))
    open_cycle = conn.execute(
        f"SELECT 1 FROM cycles WHERE state NOT IN ({placeholders}) LIMIT 1",  # noqa: S608
        FINISHED,
    ).fetchone()
    return open_cycle is not None


def _connect(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise Refused(409, "There is no run database yet. Start a run first.")
    conn = sqlite3.connect(
        f"{path.resolve().as_uri()}?mode=rw", uri=True, timeout=LOCK_SECONDS, isolation_level=None
    )
    conn.row_factory = sqlite3.Row
    try:
        version = conn.execute("SELECT version FROM schema_version").fetchone()
    except sqlite3.OperationalError:
        version = None
    if version is None or version[0] != db.SCHEMA_VERSION:
        conn.close()
        raise Refused(409, "The database is from another version of the arena. Nothing written.")
    return conn


def _write(path: Path, write) -> None:
    conn = _connect(path)
    try:
        with db.transaction(conn):
            write(conn)
    except sqlite3.OperationalError as error:
        if "locked" in str(error) or "busy" in str(error):
            raise Refused(503, "The run is writing. Try again in a moment.") from error
        raise
    finally:
        conn.close()


def set_control(path: Path, action: str) -> str:
    if action not in db.CONTROL_TARGETS:
        raise Refused(404, f"Unknown control action. Known: {sorted(db.CONTROL_TARGETS)}.")
    state = db.CONTROL_TARGETS[action]
    _write(path, lambda conn: db.set_control(conn, state, f"operator: {action}"))
    return state


def add_note(path: Path, text: object) -> int:
    if not isinstance(text, str) or not text.strip():
        raise Refused(422, "A note needs some text.")
    if len(text) > NOTE_CHARS:
        raise Refused(422, f"A note may be at most {NOTE_CHARS} characters.")
    added: list[int] = []

    def write(conn: sqlite3.Connection) -> None:
        if notes_blocked(conn):
            raise Refused(409, "A run is mid-cycle and this database holds more than one run.")
        added.append(Memory(conn).add_operator_note(text.strip()))

    _write(path, write)
    return added[0]
