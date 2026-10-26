from pathlib import Path

import pytest

from arena import cli, db
from arena.judge_client import REPO_ROOT

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
