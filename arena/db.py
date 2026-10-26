"""The agent-facing SQLite database: cycles, stored model outputs, controls, events and memory.

Only orchestrator-side code opens this. Agents never do: they reach memory through
`arena.memory.memory` and everything else through the dispatcher. The Judge has its own database,
defined inside `arena/judge/`, which nothing here can open.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1

CYCLE_STATES = ("planned", "running", "evaluating", "committed", "rolled_back")
CONTROL_STATES = ("running", "paused", "stopped")

SCHEMA = f"""
CREATE TABLE schema_version (version INTEGER NOT NULL);

CREATE TABLE cycles (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN {CYCLE_STATES}),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Raw output of every model call. A retry is a new attempt, never an overwrite.
CREATE TABLE llm_calls (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL,
    step TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    role TEXT NOT NULL,
    model_id TEXT NOT NULL,
    backend TEXT NOT NULL,
    raw_output TEXT NOT NULL,
    valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
    failure TEXT,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE (cycle_id, step, attempt)
);

-- One row per completed group of writes. Its presence is what makes a resumed step skip them.
CREATE TABLE step_writes (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL,
    step TEXT NOT NULL,
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (cycle_id, step, kind)
);

CREATE TABLE control (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state TEXT NOT NULL CHECK (state IN {CONTROL_STATES}),
    reason TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'anomaly')),
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE usage (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    model_id TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    headroom REAL,
    created_at TEXT NOT NULL
);

CREATE TABLE manifests (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    cycle_id INTEGER NOT NULL,
    model_ids TEXT NOT NULL,
    seed INTEGER NOT NULL,
    config_hash TEXT NOT NULL,
    git_sha TEXT NOT NULL,
    constitution_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (cycle_id)
);

CREATE TABLE memory_episodic (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE memory_lessons (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    scope_tags TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'disputed', 'retired')),
    cycle_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE memory_operator_notes (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE memory_backlog (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('proposed', 'running', 'confirmed', 'refuted', 'abandoned')),
    justification TEXT,
    cycle_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE memory_predictions (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL,
    expected_delta REAL NOT NULL,
    confidence REAL NOT NULL,
    actual_delta REAL,
    created_at TEXT NOT NULL
);

CREATE TABLE memory_provenance (
    id INTEGER PRIMARY KEY,
    table_name TEXT NOT NULL,
    row_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    cycle_id INTEGER NOT NULL,
    step TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- The episodic log is append-only and operator notes are never edited by code.
CREATE TRIGGER episodic_no_update BEFORE UPDATE ON memory_episodic
BEGIN SELECT RAISE(ABORT, 'memory_episodic is append-only'); END;
CREATE TRIGGER episodic_no_delete BEFORE DELETE ON memory_episodic
BEGIN SELECT RAISE(ABORT, 'memory_episodic is append-only'); END;
CREATE TRIGGER notes_no_update BEFORE UPDATE ON memory_operator_notes
BEGIN SELECT RAISE(ABORT, 'operator notes are never edited by code'); END;
CREATE TRIGGER notes_no_delete BEFORE DELETE ON memory_operator_notes
BEGIN SELECT RAISE(ABORT, 'operator notes are never edited by code'); END;
"""


class DatabaseIntegrityError(RuntimeError):
    """The integrity check failed. The run has been paused, if the database still allowed it."""


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def connect(
    path: Path, factory: type[sqlite3.Connection] = sqlite3.Connection
) -> sqlite3.Connection:
    """Open (creating if needed) the agent database, in WAL mode, after an integrity check.

    The connection is in autocommit mode; group writes with `transaction()`.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, factory=factory, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    check_integrity(conn)
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone():
        _create(conn)
    version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema is version {version}, code expects {SCHEMA_VERSION}. "
            "Move the old database aside or migrate it before running."
        )
    return conn


def _create(conn: sqlite3.Connection) -> None:
    with transaction(conn):
        for statement in _statements(SCHEMA):
            conn.execute(statement)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        conn.execute(
            "INSERT INTO control (id, state, reason, updated_at) VALUES (1, 'stopped', ?, ?)",
            ("new database", now()),
        )


def _statements(script: str) -> Iterator[str]:
    """Split the schema into statements, keeping trigger bodies whole."""
    buffer = ""
    for line in script.splitlines(keepends=True):
        if line.lstrip().startswith("--"):
            continue
        buffer += line
        if sqlite3.complete_statement(buffer):
            yield buffer.strip()
            buffer = ""


def check_integrity(conn: sqlite3.Connection) -> None:
    rows = [row[0] for row in conn.execute("PRAGMA integrity_check").fetchall()]
    if rows == ["ok"]:
        return
    detail = "; ".join(str(row) for row in rows[:5])
    try:
        set_control(conn, "paused", f"database integrity check failed: {detail}")
    except sqlite3.Error:
        # Too damaged to record the pause. The raise below still stops the run.
        pass
    raise DatabaseIntegrityError(
        f"Database integrity check failed ({detail}). The run is paused. "
        "Restore the last snapshot before resuming."
    )


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """All-or-nothing group of writes. A crash inside leaves no partial rows behind."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def control_state(conn: sqlite3.Connection) -> tuple[str, str]:
    row = conn.execute("SELECT state, reason FROM control WHERE id = 1").fetchone()
    return row["state"], row["reason"]


def set_control(conn: sqlite3.Connection, state: str, reason: str) -> None:
    if state not in CONTROL_STATES:
        raise ValueError(f"unknown control state {state!r}")
    conn.execute(
        "UPDATE control SET state = ?, reason = ?, updated_at = ? WHERE id = 1",
        (state, reason, now()),
    )


def log_event(
    conn: sqlite3.Connection,
    kind: str,
    detail: dict,
    *,
    cycle_id: int | None = None,
    severity: str = "info",
) -> None:
    conn.execute(
        "INSERT INTO events (cycle_id, kind, severity, detail, created_at) VALUES (?, ?, ?, ?, ?)",
        (cycle_id, kind, severity, json.dumps(detail, sort_keys=True), now()),
    )


def raise_anomaly(
    conn: sqlite3.Connection, kind: str, detail: dict, *, cycle_id: int | None = None
) -> None:
    """Record an anomaly and pause the run. The operator decides when it resumes."""
    log_event(conn, kind, detail, cycle_id=cycle_id, severity="anomaly")
    set_control(conn, "paused", f"anomaly: {kind}")
