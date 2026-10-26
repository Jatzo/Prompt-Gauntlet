"""The agent-facing SQLite database: cycles, stored model outputs, controls, events and memory.

Only orchestrator-side code opens this. Agents never do: they reach memory through
`arena.memory.memory` and everything else through the dispatcher. The Judge has its own database,
defined inside `arena/judge/`, which nothing here can open.
"""

import json
import os
import socket
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 3

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

DETECTOR_STATUSES = (
    "baseline",
    "candidate",
    "not_kept",
    "kept_provisional",
    "kept_reviewed",
    "rejected",
)

# Added in version 2: the runner row, and the lineage of detector configs (PLAN section 10).
VERSION_2 = f"""
-- The process allowed to run cycles against this database. One row at most.
CREATE TABLE runner (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    pid INTEGER NOT NULL,
    host TEXT NOT NULL,
    claimed_at TEXT NOT NULL
);

-- Every detector config ever proposed, with its parent. The incumbent is the newest kept one.
CREATE TABLE detector_configs (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER REFERENCES detector_configs (id),
    config TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN {DETECTOR_STATUSES}),
    known_good INTEGER NOT NULL DEFAULT 0 CHECK (known_good IN (0, 1)),
    cycle_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""

# Added in version 3: the novelty archive (PLAN section 10), written only through memory.py. Reads
# are scoped to one run through the cycle, so each run starts with an empty archive.
VERSION_3 = """
CREATE TABLE novelty_archive (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL,
    cluster_id TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

# Each entry upgrades a database from that version to the next.
MIGRATIONS = {1: VERSION_2, 2: VERSION_3}


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
    if _version(conn) < SCHEMA_VERSION:
        _create_or_migrate(conn)
    version = _version(conn)
    if version != SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema is version {version}, code expects {SCHEMA_VERSION}. "
            "Move the old database aside or migrate it before running."
        )
    return conn


def _version(conn: sqlite3.Connection) -> int:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    return conn.execute("SELECT version FROM schema_version").fetchone()[0] if exists else 0


def _create_or_migrate(conn: sqlite3.Connection) -> None:
    with transaction(conn):
        # Read again under the write lock: another process may have created or migrated it.
        version = _version(conn)
        if version == 0:
            _create(conn)
            return
        while version < SCHEMA_VERSION:
            for statement in _statements(MIGRATIONS[version]):
                conn.execute(statement)
            version += 1
        conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))


def _create(conn: sqlite3.Connection) -> None:
    for statement in _statements(SCHEMA + VERSION_2 + VERSION_3):
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


class RunnerBusy(RuntimeError):
    """Another live process holds the runner row, so this one may not run cycles."""


def _alive(pid: int, host: str) -> bool:
    """Whether the process that claimed the runner row still holds it.

    Pids are reused after a crash or a restart, so a live pid only counts when its command line is
    an arena process. Where /proc cannot say, a live pid counts as the holder.
    """
    if host != socket.gethostname():
        # A process on another machine cannot be checked from here, so it counts as alive.
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return True
    return b"arena" in command


@contextmanager
def runner(conn: sqlite3.Connection) -> Iterator[None]:
    """Hold the runner row while running cycles or changing them from the CLI.

    The row is claimed inside one write transaction, so two processes cannot both see it free. A row
    left by a process that has died is taken over.
    """
    pid, host = os.getpid(), socket.gethostname()
    with transaction(conn):
        row = conn.execute("SELECT pid, host, claimed_at FROM runner WHERE id = 1").fetchone()
        if row is not None and (row["pid"], row["host"]) != (pid, host):
            if _alive(row["pid"], row["host"]):
                raise RunnerBusy(
                    f"Process {row['pid']} on {row['host']} has been running cycles since "
                    f"{row['claimed_at']}. Wait for it to finish, or stop it first."
                )
        conn.execute(
            "INSERT OR REPLACE INTO runner (id, pid, host, claimed_at) VALUES (1, ?, ?, ?)",
            (pid, host, now()),
        )
    try:
        yield
    finally:
        conn.execute("DELETE FROM runner WHERE id = 1 AND pid = ? AND host = ?", (pid, host))
