from pathlib import Path

import pytest

from arena import cli, db, usage
from arena.config import REPO_ROOT

CASSETTE = REPO_ROOT / "tests" / "fixtures" / "phase1_cycle.cassette.jsonl"


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_JUDGE_DIR", str(tmp_path / "judge"))
    return str(tmp_path / "arena.db")


def test_run_cycle_refuses_until_the_run_is_started(db_path, capsys):
    assert cli.main(["--db", db_path, "run-cycle"]) == 3
    assert "control start" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("action", "state"),
    [("start", "running"), ("pause", "paused"), ("resume", "running"), ("stop", "stopped")],
)
def test_control_sets_the_run_state(db_path, action, state):
    assert cli.main(["--db", db_path, "control", action]) == 0
    conn = db.connect(Path(db_path))
    assert db.control_state(conn)[0] == state


def test_a_mock_cycle_commits_from_the_command_line(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    assert cli.main(["--db", db_path, "run-cycle", "--backend", "mock"]) == 0
    assert "committed" in capsys.readouterr().out


def test_a_replay_cycle_commits_from_a_cassette(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    args = ["--db", db_path, "run-cycle", "--backend", "replay", "--cassette", str(CASSETTE)]
    assert cli.main(args) == 0
    assert "committed" in capsys.readouterr().out


def test_status_reports_the_run(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    cli.main(["--db", db_path, "run-cycle"])
    capsys.readouterr()
    assert cli.main(["--db", db_path, "status"]) == 0
    out = capsys.readouterr().out
    assert "Control: running" in out
    assert "Latest cycle: 1 (committed)" in out
    assert "Schema failures, ceo: 0% of the last 2 calls" in out


def test_status_reports_the_same_token_total_as_the_usage_ledger(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    cli.main(["--db", db_path, "run-cycle"])
    capsys.readouterr()
    cli.main(["--db", db_path, "status"])
    total = usage.total_tokens(db.connect(Path(db_path)))
    assert total > 0
    assert f"Tokens used: {total}" in capsys.readouterr().out


def test_run_cycle_refuses_while_another_process_holds_the_runner(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    conn = db.connect(Path(db_path))
    conn.execute(
        "INSERT INTO runner (id, pid, host, claimed_at) VALUES (1, 1, 'another-machine', 'then')"
    )
    conn.close()
    assert cli.main(["--db", db_path, "run-cycle", "--backend", "mock"]) == 1
    assert "another-machine" in capsys.readouterr().err


def test_abandon_cycle_rolls_back_the_open_cycle_and_keeps_its_outputs(db_path, capsys):
    from arena import cycle

    conn = db.connect(Path(db_path))
    cycle_id = cycle.open_cycle(conn, "default")
    conn.execute(
        "INSERT INTO llm_calls (cycle_id, step, attempt, role, model_id, backend, raw_output,"
        " valid, created_at) VALUES (?, 'plan', 0, 'ceo', 'm', 'mock', '{}', 1, 't')",
        (cycle_id,),
    )
    assert cli.main(["--db", db_path, "abandon-cycle", "--reason", "config changed"]) == 0
    assert cycle.state(conn, cycle_id) == "rolled_back"
    assert conn.execute("SELECT COUNT(*) FROM llm_calls").fetchone()[0] == 1
    event = conn.execute("SELECT detail FROM events WHERE kind = 'cycle_abandoned'").fetchone()
    assert "config changed" in event["detail"]
    assert cli.main(["--db", db_path, "abandon-cycle", "--reason", "again"]) == 0
    assert "no open cycle" in capsys.readouterr().out


def test_data_build_writes_the_synthetic_dataset_and_reports_its_shortfalls(tmp_path, capsys):
    judge_dir = tmp_path / "judge"
    args = ["data", "build", "--synthetic", "--judge-dir", str(judge_dir)]
    code = cli.main([*args, "--private-dir", str(tmp_path / "private")])
    assert (judge_dir / "partitions" / "dev.jsonl").exists()
    # 440 synthetic samples cannot fill the default partition sizes, and the command says so.
    assert code == 3
    assert "Short: dev has" in capsys.readouterr().out
