"""Operator commands: status, control, and running one cycle.

python -m arena.cli status
python -m arena.cli control start|pause|resume|stop
python -m arena.cli run-cycle --backend mock|replay [--cassette PATH]
"""

import argparse
import sys
from pathlib import Path

from arena import db, llm, usage
from arena.config import agent_db_path
from arena.judge_client import JudgeClient
from arena.orchestrator import Orchestrator, phase1_mock_script

CONTROL_TARGETS = {"start": "running", "resume": "running", "pause": "paused", "stop": "stopped"}


def cmd_status(conn) -> int:
    state, reason = db.control_state(conn)
    print(f"Control: {state} ({reason})")
    row = conn.execute("SELECT id, state FROM cycles ORDER BY id DESC LIMIT 1").fetchone()
    print(f"Latest cycle: {row['id']} ({row['state']})" if row else "Latest cycle: none yet")
    print(f"Tokens used: {usage.total_tokens(conn)}")
    for (role,) in conn.execute("SELECT DISTINCT role FROM llm_calls ORDER BY role"):
        rate, calls = llm.schema_failure_rate(conn, role)
        print(f"Schema failures, {role}: {rate:.0%} of the last {calls} calls")
    anomalies = conn.execute(
        "SELECT kind, created_at FROM events WHERE severity = 'anomaly' ORDER BY id DESC LIMIT 5"
    ).fetchall()
    for kind, created_at in anomalies:
        print(f"Anomaly: {kind} at {created_at}")
    return 0


def cmd_control(conn, action: str) -> int:
    with db.transaction(conn):
        db.set_control(conn, CONTROL_TARGETS[action], f"operator: {action}")
    print(f"Control is now {CONTROL_TARGETS[action]}.")
    return 0


def cmd_run_cycle(conn, backend_name: str, cassette: Path | None, run_id: str) -> int:
    state, reason = db.control_state(conn)
    if state != "running":
        print(f"The run is {state} ({reason}). Start it with: python -m arena.cli control start")
        return 3
    backend = llm.get_backend(backend_name, mock_script=phase1_mock_script(), cassette=cassette)
    with JudgeClient() as judge:
        outcome = Orchestrator(conn, backend=backend, judge=judge, run_id=run_id).run_cycle()
    print(f"Cycle {outcome.cycle_id}: {outcome.status} ({outcome.detail})")
    return {"committed": 0, "paused": 3, "stopped": 3}.get(outcome.status, 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m arena.cli")
    parser.add_argument(
        "--db", type=Path, default=None, help="agent database (default runs/arena.db)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    control = commands.add_parser("control")
    control.add_argument("action", choices=sorted(CONTROL_TARGETS))
    run = commands.add_parser("run-cycle")
    run.add_argument("--backend", choices=["mock", "replay"], default="mock")
    run.add_argument("--cassette", type=Path, default=None)
    run.add_argument("--run-id", default="default")
    args = parser.parse_args(argv)

    conn = db.connect(args.db or agent_db_path())
    try:
        if args.command == "status":
            return cmd_status(conn)
        if args.command == "control":
            return cmd_control(conn, args.action)
        return cmd_run_cycle(conn, args.backend, args.cassette, args.run_id)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
