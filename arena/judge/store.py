"""The Judge-only database. Only the Judge process opens it.

Anything the Judge runs through a model (grading, detector scoring on test samples) stores its raw
output here rather than in the agent database, so per-sample test results can never land where
memory or briefing code reads.
"""

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = [
    "CREATE TABLE schema_version (version INTEGER NOT NULL)",
    """CREATE TABLE llm_calls (
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
    )""",
    """CREATE TABLE usage (
        id INTEGER PRIMARY KEY,
        cycle_id INTEGER NOT NULL,
        role TEXT NOT NULL,
        model_id TEXT NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        headroom REAL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE events (
        id INTEGER PRIMARY KEY,
        cycle_id INTEGER,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        detail TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE evaluations (
        id INTEGER PRIMARY KEY,
        cycle_id INTEGER NOT NULL,
        report TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
]


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise RuntimeError(f"Judge database at {path} failed its integrity check.")
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if not exists:
        conn.execute("BEGIN IMMEDIATE")
        for statement in SCHEMA:
            conn.execute(statement)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        conn.execute("COMMIT")
    return conn
