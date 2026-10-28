import os
import socket
import sqlite3
import subprocess
import sys

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
    "runner",
    "detector_configs",
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


def hold_runner(conn, pid, host=None):
    conn.execute(
        "INSERT OR REPLACE INTO runner (id, pid, host, claimed_at) VALUES (1, ?, ?, 'then')",
        (pid, host or socket.gethostname()),
    )


def test_a_live_runner_keeps_a_second_one_out(conn):
    # The trailing argument puts "arena" in its command line, as a real runner's would be.
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "arena"])
    try:
        hold_runner(conn, other.pid)
        with pytest.raises(db.RunnerBusy, match=str(other.pid)), db.runner(conn):
            pass
    finally:
        other.kill()
        other.wait()


def test_a_runner_left_by_a_dead_process_is_taken_over_and_released(conn):
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    hold_runner(conn, dead.pid)
    with db.runner(conn):
        row = conn.execute("SELECT pid FROM runner").fetchone()
        assert row["pid"] == os.getpid()
    assert conn.execute("SELECT COUNT(*) FROM runner").fetchone()[0] == 0


def test_a_version_1_database_gains_the_runner_table_and_keeps_its_rows(tmp_path):
    path = tmp_path / "arena.db"
    old = sqlite3.connect(path, isolation_level=None)
    for statement in db._statements(db.SCHEMA):
        old.execute(statement)
    old.execute("INSERT INTO schema_version (version) VALUES (1)")
    old.execute(
        "INSERT INTO cycles (run_id, state, created_at, updated_at)"
        " VALUES ('r', 'planned', 't', 't')"
    )
    old.close()
    conn = db.connect(path)
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == db.SCHEMA_VERSION
    assert conn.execute("SELECT COUNT(*) FROM cycles").fetchone()[0] == 1
    with db.runner(conn):
        pass


def test_a_reused_pid_that_is_not_an_arena_process_does_not_hold_the_runner(conn):
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        hold_runner(conn, unrelated.pid)
        with db.runner(conn):
            assert conn.execute("SELECT pid FROM runner").fetchone()["pid"] == os.getpid()
    finally:
        unrelated.kill()
        unrelated.wait()


def test_a_version_3_database_gains_the_judge_backend_column_and_keeps_its_manifests(tmp_path):
    path = tmp_path / "arena.db"
    old = sqlite3.connect(path, isolation_level=None)
    for statement in db._statements(db.SCHEMA + db.VERSION_2 + db.VERSION_3):
        old.execute(statement)
    old.execute("INSERT INTO schema_version (version) VALUES (3)")
    old.execute(
        "INSERT INTO manifests (run_id, cycle_id, model_ids, seed, config_hash, git_sha,"
        " constitution_hash, created_at) VALUES ('r', 1, '{}', 1, 'h', 'g', 'c', 't')"
    )
    old.close()
    conn = db.connect(path)
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == db.SCHEMA_VERSION
    assert conn.execute("SELECT judge_backend FROM manifests").fetchone()[0] is None
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE manifests SET judge_backend = 'staging'")
