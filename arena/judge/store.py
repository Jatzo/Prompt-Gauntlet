"""The Judge-only database. Only the Judge process opens it.

Anything the Judge runs through a model (grading, detector scoring, target-app turns) stores its raw
output here rather than in the agent database, so per-sample results can never land where memory or
briefing code reads.

Schema version 2 adds `eval_cache`: the final raw output for each evaluation request key, valid or
not. There is deliberately no table of per-sample scores or outcomes; those are derived again from
the cache on every measurement, so nothing can disagree with it.
"""

import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from arena.llm import CachedOutput

SCHEMA_VERSION = 3

_V1 = [
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

_V2 = [
    """CREATE TABLE eval_cache (
        key TEXT PRIMARY KEY,
        item_id TEXT NOT NULL,
        raw_output TEXT NOT NULL,
        valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
        failure TEXT,
        model_id TEXT NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )""",
]

# Rows cached before version 3 have no recorded backend.
_V3 = ["ALTER TABLE eval_cache ADD COLUMN backend TEXT NOT NULL DEFAULT ''"]


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise RuntimeError(f"Judge database at {path} failed its integrity check.")
    version = _version(conn)
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"Judge database at {path} is schema {version}, "
            f"newer than this code ({SCHEMA_VERSION})."
        )
    if version < SCHEMA_VERSION:
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Read again under the write lock: another Judge may have migrated in the meantime.
            version = _version(conn)
            if version < 1:
                for statement in _V1:
                    conn.execute(statement)
                conn.execute("INSERT INTO schema_version (version) VALUES (0)")
            if version < 2:
                for statement in _V2:
                    conn.execute(statement)
            if version < 3:
                for statement in _V3:
                    conn.execute(statement)
            conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return conn


def _version(conn: sqlite3.Connection) -> int:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    return conn.execute("SELECT version FROM schema_version").fetchone()[0] if exists else 0


class EvalCache:
    """The Judge's evaluation cache, in the shape `arena.llm.call_batch` expects."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def lookup_many(self, keys: Sequence[str]) -> dict[str, CachedOutput]:
        found: dict[str, CachedOutput] = {}
        # SQLite limits the number of bound parameters, so look keys up in chunks.
        for start in range(0, len(keys), 500):
            chunk = list(keys[start : start + 500])
            # Only "?" placeholders are joined in; every key is passed as a bound parameter.
            placeholders = ",".join("?" * len(chunk))
            query = (
                "SELECT key, item_id, raw_output, valid, failure, model_id, input_tokens,"  # noqa: S608
                f" output_tokens, backend FROM eval_cache WHERE key IN ({placeholders})"
            )
            rows = self.conn.execute(query, chunk)
            for row in rows:
                found[row[0]] = CachedOutput(
                    key=row[0],
                    item_id=row[1],
                    raw_output=row[2],
                    valid=bool(row[3]),
                    failure=row[4],
                    model_id=row[5],
                    input_tokens=row[6],
                    output_tokens=row[7],
                    backend=row[8],
                )
        return found

    def store_many(self, outputs: Sequence[CachedOutput]) -> None:
        stamp = datetime.now(UTC).isoformat(timespec="milliseconds")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.executemany(
                "INSERT OR REPLACE INTO eval_cache (key, item_id, raw_output, valid, failure,"
                " model_id, input_tokens, output_tokens, created_at, backend)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        output.key,
                        output.item_id,
                        output.raw_output,
                        int(output.valid),
                        output.failure,
                        output.model_id,
                        output.input_tokens,
                        output.output_tokens,
                        stamp,
                        output.backend,
                    )
                    for output in outputs
                ],
            )
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def entries(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM eval_cache").fetchone()[0]

    def usage_for(self, model_id: str, backend: str) -> tuple[int, int]:
        """Tokens spent on one model's calls through one backend, and how many calls that was.
        Mock token counts are estimates, so they never mix with live ones."""
        row = self.conn.execute(
            "SELECT COALESCE(SUM(input_tokens + output_tokens), 0), COUNT(*) FROM eval_cache"
            " WHERE model_id = ? AND backend = ?",
            (model_id, backend),
        ).fetchone()
        return row[0], row[1]

    def tokens(self) -> tuple[int, int]:
        """Input and output tokens spent on evaluation calls so far."""
        row = self.conn.execute(
            "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0) FROM eval_cache"
        ).fetchone()
        return row[0], row[1]
