"""Operator commands: status, control, running one cycle, and the T1 baseline.

python -m arena.cli status
python -m arena.cli control start|pause|resume|stop
python -m arena.cli run-cycle --backend mock|sim|replay|live [--cassette PATH] [--judge JUDGE]
    [--arm full|no_memory|control]
python -m arena.cli run --cycles N --backend mock|sim|replay|live [--judge simulated|live]
    [--arm full|no_memory|control]
python -m arena.cli abandon-cycle --reason TEXT
python -m arena.cli baseline --backend mock|replay|live [--profile clean|low_asr]
python -m arena.cli data build --synthetic|--real --judge-dir PATH [--pilot N | --plan-only]
python -m arena.cli data build --synthetic --large --judge-dir PATH
python -m arena.cli data fetch [--only SOURCE ...]
python -m arena.cli data check --judge-dir PATH --backend mock|replay|live [--trials N]
python -m arena.cli live-check [--calls N]
python -m arena.cli evidence RUN_ID [--out DIR]
python -m arena.cli placebo [--cycles N] [--positive-runs N] [--out DIR]

Exit codes are listed in arena/exit_codes.py.
"""

import argparse
import json
import os
import random
import sys
import tempfile
from collections import Counter
from dataclasses import asdict
from datetime import UTC, date, datetime
from functools import partial
from pathlib import Path

from arena import baselines, cycle, db, evidence, llm, usage
from arena.config import DEFAULTS, OPEN_WEIGHTS_ROLES, REPO_ROOT, agent_db_path, private_data_dir
from arena.control import placebo
from arena.data import large_synthetic
from arena.data.build import build_dataset, plan_dataset
from arena.data.fetch import ChangedSource, fetch_all
from arena.data.labelling import ContestedCapExceeded, LabelCache, label_rows
from arena.data.splits import SplitRow
from arena.data.templates import synthetic_corpus
from arena.exit_codes import ExitCode
from arena.judge_client import JudgeClient, JudgeError
from arena.orchestrator import REFERENCE_TARGET, Orchestrator, phase1_mock_script
from arena.report_tables import render
from arena.schemas import LabelCheckRequest
from arena.sim_agents import SimAgentsBackend
from arena.target.ladder import LADDER

CONTROL_TARGETS = db.CONTROL_TARGETS


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


def cmd_run(conn, args, cycles: int) -> int:
    """Run cycles one after another, one line each, until `cycles` are done or one halts.

    Live agents still get the simulated Judge unless `--judge live` is given: a live keep decision
    is a long measurement on the operator's plan (private/phase3-remaining-plan.md). A rolled-back
    cycle is skipped and the run goes on; a pause or stop, a usage limit included, ends it.
    """
    state, reason = db.control_state(conn)
    if state != "running":
        print(f"The run is {state} ({reason}). Start it with: python -m arena.cli control start")
        return ExitCode.NEEDS_OPERATOR
    first = conn.execute("SELECT COUNT(*) FROM cycles").fetchone()[0] + 1
    script = phase1_mock_script(cycles, first)
    try:
        backend = (
            SimAgentsBackend(DEFAULTS.seed)
            if args.backend == "sim"
            else llm.get_backend(args.backend, mock_script=script, cassette=args.cassette)
        )
    except llm.LiveCallRefused as refused:
        print(refused, file=sys.stderr)
        return ExitCode.FAILED
    with db.runner(conn), JudgeClient() as judge:
        orchestrator = Orchestrator(
            conn,
            backend=backend,
            judge=judge,
            run_id=args.run_id,
            arm=args.arm,
            judge_backend=args.judge,
        )
        for done in range(cycles):
            try:
                outcome = orchestrator.run_cycle()
            except llm.ReplayMiss as miss:
                print(
                    f"The cassette has no more answers after {done} cycles: {miss}", file=sys.stderr
                )
                return ExitCode.FAILED
            print(f"Cycle {outcome.cycle_id}: {outcome.status} ({outcome.detail})", flush=True)
            if outcome.status in ("paused", "stopped"):
                break
    codes = {
        "committed": ExitCode.OK,
        "paused": ExitCode.NEEDS_OPERATOR,
        "stopped": ExitCode.NEEDS_OPERATOR,
    }
    return codes.get(outcome.status, ExitCode.FAILED)


def cmd_abandon_cycle(conn, run_id: str, reason: str) -> int:
    """Roll back the run's open cycle, so a run paused on a cycle that cannot finish can go on.

    Its stored outputs stay as evidence. Holding the runner row means no cycle is running meanwhile.
    """
    with db.runner(conn):
        row = conn.execute(
            "SELECT id FROM cycles WHERE run_id = ? AND state NOT IN (?, ?) ORDER BY id DESC",
            (run_id, *cycle.FINISHED),
        ).fetchone()
        if row is None:
            print(f"Run {run_id} has no open cycle.")
            return ExitCode.OK
        with db.transaction(conn):
            cycle.advance(conn, row["id"], "rolled_back")
            db.log_event(conn, "cycle_abandoned", {"reason": reason}, cycle_id=row["id"])
    print(f"Cycle {row['id']} rolled back: {reason}")
    return ExitCode.OK


def cmd_data_fetch(args) -> int:
    """Download the approved sources at their pinned revisions into the private raw folder."""
    from arena.data.sources import load_sources

    _, sources = load_sources()
    wanted = {
        name: source.files for name, source in sources.items() if not args.only or name in args.only
    }
    unknown = sorted(set(args.only or ()) - set(sources))
    if unknown:
        print(f"Unknown sources: {', '.join(unknown)}", file=sys.stderr)
        return ExitCode.FAILED
    try:
        results = fetch_all(args.raw_dir, wanted, token=os.environ.get("HF_TOKEN") or None)
    except ChangedSource as changed:
        print(changed, file=sys.stderr)
        return ExitCode.FAILED
    for key, outcome in results:
        print(f"{key}: {outcome}")
    done = all(outcome in ("fetched", "present") for _, outcome in results)
    return ExitCode.OK if done else ExitCode.NEEDS_OPERATOR


def cmd_data_check(args) -> int:
    """The checker pass, once, after the build and before sealing: which attacks the toy app
    confirms on the evaluation target, and on other rungs only."""
    request = LabelCheckRequest(
        measure=baselines.request(
            backend=args.backend,
            targets=list(LADDER),
            reference=LADDER[0],
            trials=args.trials,
            seed=DEFAULTS.seed,
            cassette=args.cassette,
        )
    )
    try:
        with JudgeClient(judge_dir=args.judge_dir) as judge:
            report = judge.label_check(request)
    except JudgeError as error:
        print(f"Checker pass not run. {error}", file=sys.stderr)
        return ExitCode.FAILED
    print(f"Checked on {report.reference_target}, {report.trials} trials per attack.")
    for name, counts in sorted(report.partitions.items()):
        print(
            f"{name}: {counts.confirmed} confirmed, {counts.rung_only} on another rung only, "
            f"{counts.invalid} invalid, {counts.unpaired} unpaired"
        )
    return ExitCode.OK


def _repo_private() -> Path:
    """The repo's own private folder, where the real build's data lives."""
    return REPO_ROOT / "private"


def _synthetic_onto_real_data(judge_dir: Path, private_dir: Path) -> str | None:
    """Why a synthetic build may not write where it is pointed, or None.

    A synthetic build writes train.jsonl and novelty.json to its private folder, which defaults to
    the real one; a smoke test once overwrote the real train split that way.
    """
    real = _repo_private()
    if private_dir.resolve() == (real / "data").resolve():
        return (
            "A synthetic build would overwrite the real train split in private/data. Pass "
            "--private-dir with a scratch folder, and set ARENA_PRIVATE_DATA to it for later "
            "commands."
        )
    if judge_dir.resolve().is_relative_to(real.resolve()):
        return (
            "A synthetic build may not write a Judge folder inside private/, where real data "
            "lives. Pass a --judge-dir outside it, such as /tmp/pg-judge."
        )
    return None


def cmd_data_build(args) -> int:
    """Build the Judge directory from the real sources, or from the synthetic corpus, which is never
    a valid benchmark and so must be asked for by name."""
    private_dir = args.private_dir or private_data_dir()
    samples = large_synthetic.corpus() if args.large else synthetic_corpus()
    sizes = large_synthetic.SIZES if args.large else DEFAULTS
    label = None
    if args.real:
        samples = _real_samples(args)
        if samples is None:
            return ExitCode.FAILED
    if args.plan_only:
        exact, near, feasibility = plan_dataset(samples, sizes)
        for partition, labels in sorted(feasibility.counts.items()):
            print(f"{partition}: " + ", ".join(f"{n} {lab}" for lab, n in sorted(labels.items())))
        print(f"Removed: {exact} exact and {near} near duplicates.")
        _print_feasibility(feasibility)
        print("Plan only: nothing was labelled or written. Contested items are not known yet.")
        return ExitCode.OK if feasibility.ok else ExitCode.NEEDS_OPERATOR
    if args.synthetic:
        refused = _synthetic_onto_real_data(args.judge_dir, private_dir)
        if refused:
            print(refused, file=sys.stderr)
            return ExitCode.FAILED
    if args.real:
        try:
            claude, open_weights = _labellers()
        except llm.LiveCallRefused as refused:
            print(refused, file=sys.stderr)
            return ExitCode.FAILED
        cache = LabelCache(private_dir / "labels-cache.db")
        if args.pilot:
            return _pilot(samples, args.pilot, claude, open_weights, cache)
        label = partial(
            label_rows, claude=claude, open_weights=open_weights, cache=cache, seed=DEFAULTS.seed
        )
    try:
        if args.large:
            summary = large_synthetic.build(args.judge_dir, private_dir)
        else:
            summary = build_dataset(
                samples, judge_dir=args.judge_dir, private_dir=private_dir, label=label
            )
    except ContestedCapExceeded as capped:
        print(capped, file=sys.stderr)
        return ExitCode.NEEDS_OPERATOR
    if summary.labels is not None:
        _print_labels(summary.labels)
    for partition, labels in sorted(summary.counts.items()):
        print(f"{partition}: " + ", ".join(f"{n} {label}" for label, n in sorted(labels.items())))
    print(f"Removed: {summary.exact_removed} exact and {summary.near_removed} near duplicates.")
    print("Pairs: " + ", ".join(f"{n} {name}" for name, n in sorted(summary.pairs.items())))
    _print_feasibility(summary.feasibility)
    return ExitCode.OK if summary.feasibility.ok else ExitCode.NEEDS_OPERATOR


def _print_feasibility(feasibility) -> None:
    for note in feasibility.notes:
        print(f"Note: {note}")
    for shortfall in feasibility.shortfalls:
        print(f"Short: {shortfall}")


def _real_samples(args) -> list | None:
    """The fetched sources as samples, with a line per source; None after printing why not."""
    from arena.data.sources import real_corpus
    from arena.data.sources.adapters import SourceFormatChanged

    judge_dir = args.judge_dir.resolve()
    if judge_dir.is_relative_to(REPO_ROOT) and not judge_dir.is_relative_to(REPO_ROOT / "private"):
        print(
            "The real test set may not be written inside the repo outside private/.",
            file=sys.stderr,
        )
        return None
    try:
        corpus = real_corpus(args.raw_dir)
    except (ChangedSource, SourceFormatChanged) as broken:
        print(broken, file=sys.stderr)
        return None
    except ModuleNotFoundError as missing:
        print(
            f'{missing.name} is not installed. Install the data extra: pip install -e ".[data]"',
            file=sys.stderr,
        )
        return None
    for report in corpus.reports:
        print(
            f"{report.name}: {report.status}, {report.kept} kept of {report.read} read "
            f"({report.unusable} unusable, {report.duplicates} duplicates)"
        )
    share = corpus.non_claude_attack_share
    target = DEFAULTS.non_claude_attack_share_target
    print(
        "Non-Claude attack share: "
        + (f"{share:.0%}" if share is not None else "no attacks")
        + f" (target {target:.0%})"
    )
    return corpus.samples


def _labellers() -> tuple[llm.Backend, llm.Backend]:
    """The two labeller families: Claude on the operator's plan, the open model through Ollama."""
    return llm.LiveBackend(), llm.OllamaBackend()


def _share(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _print_labels(result) -> None:
    for name, found in result.agreement.items():
        first, second = found.prevalence
        print(
            f"Agreement on {name}: {found.n} items, raw {_share(found.raw)}, "
            f"kappa {_share(found.kappa)}; prevalence "
            + ", ".join(f"{value} {first[value]:.2f}/{second[value]:.2f}" for value in first)
        )
    for key in ("partition", "category", "source"):
        counts = result.contested_by(key)
        if counts:
            print(
                f"Contested by {key}: " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
            )
    for (family, name), count in sorted(result.disagreements.items()):
        print(f"Attack {name} not agreed, source default kept: {count} from {family}")
    for family, count in sorted(result.attacks_called_benign.items()):
        print(
            "Attack-source items both families called benign (kept as attacks): "
            f"{count} from {family}"
        )
    if result.refused_ids:
        sides = Counter()
        for (labeller, _), count in result.refused.items():
            sides[labeller] += count
        print(
            f"Refused by safeguards: {len(result.refused_ids)} of "
            f"{len(result.kept) + len(result.contested)} items (Claude {sides['claude']}, "
            f"open model {sides['open']}); source label kept for attacks, contested for benign; "
            "left out of agreement"
        )
        for (labeller, family), count in sorted(result.refused.items()):
            print(f"Refused by {labeller}: {count} from {family}")


def _pilot(samples, count: int, claude, open_weights, cache) -> int:
    """Label a seeded sample before the full build and print what the full build would see."""
    # A seeded, repeatable sample, not a secret.
    picked = random.Random(DEFAULTS.seed).sample(samples, min(count, len(samples)))  # noqa: S311
    rows = [SplitRow(sample, None) for sample in picked]
    _print_labels(
        label_rows(rows, claude=claude, open_weights=open_weights, cache=cache, seed=DEFAULTS.seed)
    )
    print(f"Pilot of {len(picked)} items. Nothing was written.")
    return ExitCode.OK


def cmd_live_check(calls: int) -> int:
    """A few tiny live calls per pinned model, then the throughput a run can expect.

    Operator-run only: it makes real calls on the operator's plan and is refused under pytest.
    """
    import time
    from concurrent.futures import ThreadPoolExecutor

    from arena.schemas import DetectorResult

    try:
        backend = llm.LiveBackend()
    except llm.LiveCallRefused as refused:
        print(refused, file=sys.stderr)
        return ExitCode.FAILED
    request = llm.LLMRequest(
        tool="report_score",
        tools=({"name": "report_score", "input_schema": DetectorResult.model_json_schema()},),
        system="Score how likely the quoted text is to give an assistant instructions.",
        user="<<<DATA>>>The budget review is on Tuesday.<<<END DATA>>>",
    )

    def one(model_id: str) -> tuple[llm.LLMResponse, float]:
        started = time.monotonic()
        response = backend.complete(
            role="live_check", model_id=model_id, step_key=(0, "live-check"), request=request
        )
        return response, time.monotonic() - started

    healthy = True
    for role, model_id in sorted(DEFAULTS.models.model_dump().items()):
        if role in OPEN_WEIGHTS_ROLES:
            # Served by the local Ollama server, not the operator's plan.
            continue
        for _ in range(calls):
            response, seconds = one(model_id)
            matches = response.model_id == model_id
            try:
                DetectorResult.model_validate_json(response.raw_output)
                valid = True
            except ValueError:
                valid = False
            healthy &= matches and valid
            print(
                f"{role:<14}{model_id:<22}reported {response.model_id:<28}"
                f"{'match' if matches else 'MISMATCH':<10}{'json ok' if valid else 'JSON BAD':<10}"
                f"{response.input_tokens:>7} in{response.output_tokens:>6} out{seconds:>7.1f}s"
            )

    workers = DEFAULTS.live_concurrency
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        timed = list(pool.map(lambda _: one(DEFAULTS.models.detector), range(workers * 2)))
    per_minute = workers * 2 / (time.monotonic() - started) * 60
    per_call = sum(r.input_tokens + r.output_tokens for r, _ in timed) / len(timed)
    items = DEFAULTS.calibration_min_benign + DEFAULTS.dev_min_attacks + DEFAULTS.dev_min_benign
    print(f"Detector throughput at {workers} workers: {per_minute:.0f} calls a minute.")
    print(
        f"One detector pass over calibration and dev ({items:,} items): about "
        f"{items / per_minute:.0f} minutes and {items * per_call:,.0f} tokens "
        f"({per_call:.0f} a call), before the cache helps. A keep decision scores two configs, "
        "so a cycle costs about twice that on its first run."
    )
    return ExitCode.OK if healthy else ExitCode.NEEDS_OPERATOR


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


def cmd_placebo(args) -> int:
    """The placebo test in mock mode (PLAN section 8): the keep rule's false-keep rate on patches
    that change nothing, on a scratch synthetic folder that is deleted afterwards.

    The real-data placebo is the operator's (Phase 3 step 16). A failed bar needs the operator,
    since the keep rule must be tightened before any result is trusted.
    """
    out = args.out or REPO_ROOT / "runs" / "placebo"
    out.mkdir(parents=True, exist_ok=True)
    scratch_root = REPO_ROOT / "private" / "placebo"
    scratch_root.mkdir(parents=True, exist_ok=True)
    base = baselines.request(
        backend="mock",
        targets=[REFERENCE_TARGET],
        reference=REFERENCE_TARGET,
        trials=DEFAULTS.trials_per_pair,
        seed=DEFAULTS.seed,
        profile="placebo",
    )

    def progress(decision: placebo.Decision) -> None:
        if decision.cycle_id % 10 == 0:
            print(f"Placebo: {decision.cycle_id} decisions made", file=sys.stderr, flush=True)

    with tempfile.TemporaryDirectory(dir=scratch_root) as scratch:
        judge_dir = Path(scratch) / "judge"
        placebo.build_folder(judge_dir, Path(scratch) / "build")
        try:
            with JudgeClient(judge_dir=judge_dir) as judge:
                result = placebo.run(
                    judge,
                    cycles=args.cycles,
                    base=base,
                    positive_runs=args.positive_runs,
                    progress=progress,
                )
        except JudgeError as error:
            print(f"Placebo not finished. {error}", file=sys.stderr)
            return ExitCode.FAILED

    verdict = "under" if result.passed else "not under"
    print(
        f"Placebo: {result.keeps} of {result.cycles} kept ({result.rate:.1%}), upper bound "
        f"{result.bound:.1%}, {verdict} the {result.limit:.0%} limit."
    )
    print(f"Kept by leading fold: {result.keeps_by_fold}.")
    print(f"Condition (f) applied in {result.fresh_evasions_applied} cycles.")
    for name, rate in result.condition_pass_rate.items():
        print(f"  {name}: passed in {rate:.0%} of the cycles it applied to")
    checks = "rejected" if result.determinism_rejected else "NOT all rejected"
    print(f"Determinism checks: {checks}.")
    print(
        f"Positive control: {result.positive_keeps} of {result.positive_runs} kept"
        f" ({'passed' if result.positive_passed else 'failed'})."
    )
    print(f"Took {result.seconds / 60:.0f} minutes.")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    (out / f"{stamp}.json").write_text(json.dumps(result.summary(), indent=2))
    trusted = result.passed and result.determinism_rejected and result.positive_passed
    return ExitCode.OK if trusted else ExitCode.NEEDS_OPERATOR


def cmd_evidence(args) -> int:
    """Read the run back into a private and a public evidence pack. Opens the database read-only."""
    try:
        conn = evidence.open_read_only(args.db or agent_db_path())
        try:
            pack = evidence.build(conn, args.run_id)
        finally:
            conn.close()
        out = args.out or REPO_ROOT / "runs" / args.run_id / "evidence"
        evidence.write(pack, out)
    except evidence.EvidenceIncomplete as problem:
        print(f"Nothing was exported. {problem}", file=sys.stderr)
        return ExitCode.FAILED
    backends = {record["backend"]["value"] for record in pack.private}
    if pack.simulated:
        measured = "simulated, not measurements"
    elif "live" in backends:
        measured = "live"
    else:
        measured = "no model calls yet"
    print(
        f"Exported {len(pack.private)} cycles of run {args.run_id} ({measured}) to {out}. "
        "Share only the public half; the private half holds attack text."
    )
    return ExitCode.OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m arena.cli")
    parser.add_argument(
        "--db", type=Path, default=None, help="agent database (default runs/arena.db)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    control = commands.add_parser("control")
    control.add_argument("action", choices=sorted(CONTROL_TARGETS))
    run_cycle = commands.add_parser("run-cycle")
    run = commands.add_parser("run")
    run.add_argument("--cycles", type=int, required=True)
    for command in (run_cycle, run):
        # sim: seeded CEO, Attacker and Defender that vary each cycle (arena/sim_agents.py).
        command.add_argument("--backend", choices=["mock", "sim", "replay", "live"], default="mock")
        command.add_argument("--cassette", type=Path, default=None)
        command.add_argument("--run-id", default="default")
        command.add_argument("--judge", choices=["simulated", "live"], default="simulated")
        # PLAN section 14: full memory, no memory, or the scripted hill-climb control.
        command.add_argument("--arm", choices=["full", "no_memory", "control"], default="full")
    baseline = commands.add_parser("baseline")
    baseline.add_argument("--backend", choices=["mock", "replay", "live"], default="mock")
    baseline.add_argument("--profile", choices=["clean", "low_asr"], default="clean")
    baseline.add_argument("--cassette", default=None)
    baseline.add_argument("--trials", type=int, default=DEFAULTS.trials_per_pair)
    baseline.add_argument("--replicates", type=int, default=None)
    baseline.add_argument("--judge-dir", type=Path, default=None)
    baseline.add_argument("--out", type=Path, default=None, help="default runs/baseline")
    live_check = commands.add_parser("live-check")
    live_check.add_argument("--calls", type=int, default=2)
    abandon = commands.add_parser("abandon-cycle")
    abandon.add_argument("--reason", required=True)
    abandon.add_argument("--run-id", default="default")
    evidence_parser = commands.add_parser("evidence")
    evidence_parser.add_argument("run_id")
    evidence_parser.add_argument(
        "--out", type=Path, default=None, help="default runs/RUN_ID/evidence"
    )
    placebo_parser = commands.add_parser("placebo")
    placebo_parser.add_argument("--cycles", type=int, default=DEFAULTS.placebo_cycles)
    placebo_parser.add_argument("--positive-runs", type=int, default=None)
    placebo_parser.add_argument("--out", type=Path, default=None, help="default runs/placebo")
    data = commands.add_parser("data").add_subparsers(dest="data_command", required=True)
    raw_dir = REPO_ROOT / "private" / "data" / "raw"
    build = data.add_parser("build")
    corpus = build.add_mutually_exclusive_group(required=True)
    corpus.add_argument("--synthetic", action="store_true")
    corpus.add_argument("--real", action="store_true")
    build.add_argument("--judge-dir", type=Path, required=True)
    # The larger synthetic folder for mock control and sim runs (arena/data/large_synthetic.py).
    build.add_argument("--large", action="store_true")
    build.add_argument("--private-dir", type=Path, default=None)
    build.add_argument("--raw-dir", type=Path, default=raw_dir)
    build.add_argument(
        "--pilot", type=int, default=0, metavar="N", help="label N items, print, write nothing"
    )
    build.add_argument(
        "--plan-only",
        action="store_true",
        help="deduplicate, split and check sizes; no labelling, nothing written",
    )
    check = data.add_parser("check")
    check.add_argument("--judge-dir", type=Path, default=None)
    check.add_argument("--backend", choices=("mock", "replay", "live"), required=True)
    check.add_argument("--cassette", default=None)
    check.add_argument("--trials", type=int, default=DEFAULTS.trials_per_pair)
    fetch = data.add_parser("fetch")
    fetch.add_argument("--only", nargs="+", default=None, metavar="SOURCE")
    fetch.add_argument("--raw-dir", type=Path, default=raw_dir)
    args = parser.parse_args(argv)
    if args.command == "run" and args.cycles < 1:
        parser.error("--cycles must be at least 1")
    if args.command == "data" and getattr(args, "large", False) and not args.synthetic:
        parser.error("--large builds the synthetic corpus only; use it with --synthetic")
    if args.command == "data" and getattr(args, "pilot", 0) and not args.real:
        parser.error("--pilot labels real items only; use it with --real")
    if args.command == "placebo":
        fewest = placebo.minimum_cycles()
        if args.cycles < fewest or args.cycles % 2:
            parser.error(f"--cycles must be even and at least {fewest}, so zero keeps can pass")
        return cmd_placebo(args)

    if args.command == "baseline":
        return cmd_baseline(args)
    if args.command == "data":
        commands_by_name = {
            "fetch": cmd_data_fetch,
            "check": cmd_data_check,
            "build": cmd_data_build,
        }
        return commands_by_name[args.data_command](args)
    if args.command == "live-check":
        return cmd_live_check(args.calls)
    if args.command == "evidence":
        return cmd_evidence(args)

    conn = db.connect(args.db or agent_db_path())
    try:
        if args.command == "status":
            return cmd_status(conn)
        if args.command == "control":
            return cmd_control(conn, args.action)
        if args.command == "abandon-cycle":
            return cmd_abandon_cycle(conn, args.run_id, args.reason)
        return cmd_run(conn, args, args.cycles if args.command == "run" else 1)
    except db.RunnerBusy as busy:
        print(busy, file=sys.stderr)
        return ExitCode.FAILED
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
