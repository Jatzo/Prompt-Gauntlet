import sqlite3

import pytest

from arena import db

EXPECTED_TABLES = {
    "schema_version",
    "cycles",
    "llm_calls",
    "step_writes",
    "control",
    "events",
    "usage",
    "manifests",
    "memory_episodic",
    "memory_lessons",
    "memory_operator_notes",
    "memory_backlog",
    "memory_predictions",
    "memory_provenance",
}


@pytest.fixture
def conn(tmp_path):
    connection = db.connect(tmp_path / "arena.db")
    yield connection
    connection.close()


def test_every_table_is_created(conn):
    names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert EXPECTED_TABLES <= names


def test_the_schema_version_is_recorded(conn):
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == db.SCHEMA_VERSION


def test_the_database_runs_in_wal_mode(conn):
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_reopening_an_existing_database_keeps_its_rows(tmp_path):
    first = db.connect(tmp_path / "arena.db")
    db.set_control(first, "running", "test")
    first.close()
    again = db.connect(tmp_path / "arena.db")
    assert db.control_state(again) == ("running", "test")


def test_a_new_database_starts_stopped(conn):
    assert db.control_state(conn)[0] == "stopped"


def test_a_stored_output_cannot_be_written_twice_for_the_same_attempt(conn):
    row = (1, "plan", 1, "ceo", "m", "mock", "{}", 1, db.now())
    insert = (
        "INSERT INTO llm_calls (cycle_id, step, attempt, role, model_id, backend, raw_output,"
        " valid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    conn.execute(insert, row)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(insert, row)


def test_a_step_cannot_record_the_same_writes_twice(conn):
    insert = (
        "INSERT INTO step_writes (cycle_id, step, kind, created_at) VALUES (1, 'plan', 'memory', ?)"
    )
    conn.execute(insert, (db.now(),))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(insert, (db.now(),))


def test_a_cycle_state_outside_the_machine_is_refused(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO cycles (run_id, state, created_at, updated_at) VALUES ('r', 'done', ?, ?)",
            (db.now(), db.now()),
        )


def test_the_episodic_log_is_append_only(conn):
    conn.execute(
        "INSERT INTO memory_episodic (cycle_id, kind, body, created_at)"
        " VALUES (1, 'plan', '{}', ?)",
        (db.now(),),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE memory_episodic SET body = 'x'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM memory_episodic")


def test_operator_notes_cannot_be_edited_or_deleted(conn):
    conn.execute(
        "INSERT INTO memory_operator_notes (text, created_at) VALUES ('look at base64', ?)",
        (db.now(),),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE memory_operator_notes SET text = 'x'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM memory_operator_notes")


def test_a_failed_transaction_leaves_nothing_behind(conn):
    with pytest.raises(RuntimeError), db.transaction(conn):
        db.log_event(conn, "half_done", {})
        raise RuntimeError("crash mid-write")
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_an_anomaly_pauses_the_run(conn):
    db.set_control(conn, "running", "test")
    db.raise_anomaly(conn, "forbidden_tool", {"role": "ceo"})
    assert db.control_state(conn) == ("paused", "anomaly: forbidden_tool")
    assert conn.execute("SELECT severity FROM events").fetchone()[0] == "anomaly"


class _CorruptConnection(sqlite3.Connection):
    """Reports a failed integrity check while still accepting writes, like a partly damaged file."""

    def execute(self, sql, *args):
        if sql.strip().upper() == "PRAGMA INTEGRITY_CHECK":
            return super().execute("SELECT 'row 3 missing from index idx_cycles'")
        return super().execute(sql, *args)


def test_a_failed_integrity_check_raises_and_pauses(tmp_path):
    path = tmp_path / "arena.db"
    healthy = db.connect(path)
    db.set_control(healthy, "running", "test")
    healthy.close()

    with pytest.raises(db.DatabaseIntegrityError):
        db.connect(path, factory=_CorruptConnection)

    assert db.control_state(db.connect(path))[0] == "paused"
