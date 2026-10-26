"""Operator commands: status, control, running one cycle, and the T1 baseline.

python -m arena.cli status
python -m arena.cli control start|pause|resume|stop
python -m arena.cli run-cycle --backend mock|replay [--cassette PATH]
python -m arena.cli baseline --backend mock|replay|live [--profile clean|low_asr]

Exit codes are listed in arena/exit_codes.py.
"""

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, date, datetime
from pathlib import Path

from arena import baselines, db, llm, usage
from arena.config import DEFAULTS, REPO_ROOT, agent_db_path
from arena.exit_codes import ExitCode
from arena.judge_client import JudgeClient, JudgeError
from arena.orchestrator import Orchestrator, phase1_mock_script
from arena.report_tables import render
from arena.target.ladder import LADDER

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
        return ExitCode.NEEDS_OPERATOR
    backend = llm.get_backend(backend_name, mock_script=phase1_mock_script(), cassette=cassette)
    with JudgeClient() as judge:
        outcome = Orchestrator(conn, backend=backend, judge=judge, run_id=run_id).run_cycle()
    print(f"Cycle {outcome.cycle_id}: {outcome.status} ({outcome.detail})")
    codes = {
        "committed": ExitCode.OK,
        "paused": ExitCode.NEEDS_OPERATOR,
        "stopped": ExitCode.NEEDS_OPERATOR,
    }
    return codes.get(outcome.status, ExitCode.FAILED)


def cmd_baseline(args) -> int:
    """Measure every baseline arm on every ladder rung, then judge the gate.

    Validity is measured against the evaluation target first. If the gate settles on a fallback
    rung, the measurement is repeated with that rung as the reference, which costs only the new
    target trials because every other call is already cached.
    """
    out = args.out or REPO_ROOT / "runs" / "baseline"
    out.mkdir(parents=True, exist_ok=True)
    started_file = out / "ladder-started"
    first_ladder_run = (
        date.fromisoformat(started_file.read_text().strip()) if started_file.exists() else None
    )

    def measure(reference):
        request = baselines.request(
            backend=args.backend,
            targets=list(LADDER),
            reference=reference,
            trials=args.trials,
            seed=DEFAULTS.seed,
            profile=args.profile,
            cassette=args.cassette,
            replicates=args.replicates,
        )
        with JudgeClient(judge_dir=args.judge_dir) as judge:
            report = judge.measure(request)
        return report, baselines.verdict(
            report, first_ladder_run=first_ladder_run, today=date.today()
        )

    try:
        report, verdict = measure(LADDER[0])
        if verdict.gate.status in ("measure_next", "fallback_pass") and first_ladder_run is None:
            started_file.write_text(date.today().isoformat())
        if verdict.gate.status == "fallback_pass" and verdict.gate.rung:
            report, verdict = measure(LADDER[verdict.gate.rung])
    except JudgeError as error:
        print(f"Baseline not measured. {error}", file=sys.stderr)
        return ExitCode.FAILED

    print(render(report, verdict))
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    saved = {"report": report.model_dump(mode="json"), "verdict": asdict(verdict)}
    (out / f"{stamp}.json").write_text(json.dumps(saved, indent=2, default=str))
    return verdict.exit_code


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
    baseline = commands.add_parser("baseline")
    baseline.add_argument("--backend", choices=["mock", "replay", "live"], default="mock")
    baseline.add_argument("--profile", choices=["clean", "low_asr"], default="clean")
    baseline.add_argument("--cassette", default=None)
    baseline.add_argument("--trials", type=int, default=DEFAULTS.trials_per_pair)
    baseline.add_argument("--replicates", type=int, default=None)
    baseline.add_argument("--judge-dir", type=Path, default=None)
    baseline.add_argument("--out", type=Path, default=None, help="default runs/baseline")
    args = parser.parse_args(argv)

    if args.command == "baseline":
        return cmd_baseline(args)

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
