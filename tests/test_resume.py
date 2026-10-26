"""Kill the process mid-cycle, restart it, and check nothing was called or written twice."""

import json
import os
import sqlite3
import subprocess
import sys
import time

from arena.config import REPO_ROOT

MARKER_TIMEOUT_SECONDS = 60


def cli(*args, env):
    return [sys.executable, "-m", "arena.cli", "--db", env["ARENA_DB"], *args]


def calls_by_step(log):
    counts = {}
    for line in log.read_text().splitlines():
        step = json.loads(line)["step"]
        counts[step] = counts.get(step, 0) + 1
    return counts


def test_a_killed_cycle_resumes_from_stored_outputs_without_calling_the_model_again(tmp_path):
    call_log = tmp_path / "calls.log"
    marker = tmp_path / "blocked"
    env = dict(
        os.environ,
        ARENA_DB=str(tmp_path / "arena.db"),
        ARENA_JUDGE_DIR=str(tmp_path / "judge"),
        ARENA_LLM_BACKEND="mock",
        ARENA_MOCK_CALL_LOG=str(call_log),
    )
    subprocess.run(cli("control", "start", env=env), env=env, cwd=REPO_ROOT, check=True)

    # First process: steps 1 (plan) and 2 (judge) commit, then the mock blocks at step 3.
    blocking = dict(env, ARENA_MOCK_BLOCK_AT_STEP="postmortem", ARENA_MOCK_BLOCK_MARKER=str(marker))
    first = subprocess.Popen(cli("run-cycle", env=env), env=blocking, cwd=REPO_ROOT)
    deadline = time.monotonic() + MARKER_TIMEOUT_SECONDS
    while not marker.exists():
        assert first.poll() is None, "the first run exited before reaching step 3"
        assert time.monotonic() < deadline, "the first run never reached step 3"
        time.sleep(0.05)
    first.kill()
    first.wait()

    agent_db = sqlite3.connect(tmp_path / "arena.db")
    assert agent_db.execute("SELECT state FROM cycles").fetchall() == [("evaluating",)]
    assert calls_by_step(call_log) == {"plan": 1}

    # Second process: same cycle, no blocking.
    second = subprocess.run(
        cli("run-cycle", env=env), env=env, cwd=REPO_ROOT, capture_output=True, text=True
    )
    assert second.returncode == 0, second.stdout + second.stderr

    assert agent_db.execute("SELECT id, state FROM cycles").fetchall() == [(1, "committed")]
    # Step 1 was called once across both processes, step 3 once, in the second process only.
    assert calls_by_step(call_log) == {"plan": 1, "postmortem": 1}
    # Step 2 is the Judge: it evaluated once, before the kill.
    judge_db = sqlite3.connect(tmp_path / "judge" / "judge.db")
    assert judge_db.execute("SELECT cycle_id FROM evaluations").fetchall() == [(1,)]
    stored = agent_db.execute("SELECT step, COUNT(*) FROM llm_calls GROUP BY step ORDER BY step")
    assert stored.fetchall() == [("plan", 1), ("postmortem", 1)]
    kinds = agent_db.execute("SELECT kind FROM memory_episodic ORDER BY id").fetchall()
    assert kinds == [("plan",), ("judge_report",), ("postmortem",)]
