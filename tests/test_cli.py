import json
from pathlib import Path

import pytest

from arena import cli, db, usage
from arena.config import REPO_ROOT
from arena.orchestrator import phase1_mock_script

CASSETTE = REPO_ROOT / "tests" / "fixtures" / "phase1_cycle.cassette.jsonl"


@pytest.fixture
def db_path(tmp_path, monkeypatch, built_judge):
    # A Defender cycle reaches the Judge's keep rule, which measures on a built data folder.
    monkeypatch.setenv("ARENA_JUDGE_DIR", str(built_judge))
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


def defender_only_script():
    """The mock cycle with a plan that does not run the Attacker. These tests cover the command
    line; the attack step against a real Judge has its own tests, with a built data folder."""
    script = phase1_mock_script()
    plan = json.loads(script["plan"][0])
    script["plan"] = [json.dumps(dict(plan, agents_to_run=["defender"]))]
    return script


def test_a_mock_cycle_commits_from_the_command_line(db_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "phase1_mock_script", defender_only_script)
    cli.main(["--db", db_path, "control", "start"])
    assert cli.main(["--db", db_path, "run-cycle", "--backend", "mock"]) == 0
    assert "committed" in capsys.readouterr().out


def test_a_replay_cycle_commits_from_a_cassette(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    args = ["--db", db_path, "run-cycle", "--backend", "replay", "--cassette", str(CASSETTE)]
    assert cli.main(args) == 0
    assert "committed" in capsys.readouterr().out


def test_status_reports_the_run(db_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "phase1_mock_script", defender_only_script)
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


def test_run_commits_one_cycle_after_another(db_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "phase1_mock_script", defender_only_script)
    cli.main(["--db", db_path, "control", "start"])
    assert cli.main(["--db", db_path, "run", "--cycles", "3", "--backend", "mock"]) == 0
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("Cycle")]
    assert [line.split(":")[0] for line in lines] == ["Cycle 1", "Cycle 2", "Cycle 3"]
    assert all("committed" in line for line in lines)


def test_run_stops_at_the_first_pause(db_path, capsys, monkeypatch):
    from arena.orchestrator import CycleOutcome

    outcomes = iter(
        [CycleOutcome("committed", 1, "all steps done"), CycleOutcome("paused", 2, "operator")]
    )
    monkeypatch.setattr(cli.Orchestrator, "run_cycle", lambda self: next(outcomes))
    cli.main(["--db", db_path, "control", "start"])
    assert cli.main(["--db", db_path, "run", "--cycles", "5"]) == 3
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("Cycle")]
    assert lines == ["Cycle 1: committed (all steps done)", "Cycle 2: paused (operator)"]


def test_live_agents_are_refused_under_pytest_before_any_cycle_opens(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    assert cli.main(["--db", db_path, "run", "--cycles", "1", "--backend", "live"]) == 1
    assert "never made from tests" in capsys.readouterr().err
    conn = db.connect(Path(db_path))
    assert conn.execute("SELECT COUNT(*) FROM cycles").fetchone()[0] == 0


@pytest.mark.parametrize(("flags", "expected"), [([], "simulated"), (["--judge", "live"], "live")])
def test_the_judge_flag_reaches_the_orchestrator(db_path, monkeypatch, flags, expected):
    from arena.orchestrator import CycleOutcome

    seen = []

    def run_cycle(self):
        seen.append(self.judge_backend)
        return CycleOutcome("committed", 1, "all steps done")

    monkeypatch.setattr(cli.Orchestrator, "run_cycle", run_cycle)
    cli.main(["--db", db_path, "control", "start"])
    assert cli.main(["--db", db_path, "run-cycle", *flags]) == 0
    assert seen == [expected]


def test_run_needs_at_least_one_cycle(db_path):
    with pytest.raises(SystemExit):
        cli.main(["--db", db_path, "run", "--cycles", "0"])


def test_a_cassette_that_runs_out_ends_the_run_with_a_message(db_path, capsys):
    cli.main(["--db", db_path, "control", "start"])
    args = ["--db", db_path, "run", "--cycles", "3", "--backend", "replay", "--cassette"]
    assert cli.main([*args, str(CASSETTE)]) == 1
    captured = capsys.readouterr()
    assert "Cycle 1: committed" in captured.out
    assert "no more answers after 1 cycles" in captured.err
