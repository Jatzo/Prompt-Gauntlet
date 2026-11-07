"""Part 2's discovery check, inside the Judge (docs/experiments/005-discovery.md).

Each of the Attacker's attacks is played in the task it names, `trials` times, on the
screening target, and the reply counts what happened over every trial. Unlike
`attacks.validate_batch` it needs no detector, splits nothing and deletes nothing. Its rows live in
their own database, `discovery.db` beside `judge.db`, keyed by run, round and index, so no
discovery round can touch an arena cycle's rows. Target calls go through the Judge's eval cache,
so a stopped round resumes with no new calls.

The band against every public attack, test included, is computed here for candidates only and
stored with the row. It is never returned, so no agent sees anything derived from the test set.
"""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from arena import novelty, taxonomy
from arena.config import DEFAULTS, private_data_dir
from arena.judge import data as judge_data
from arena.judge import measure
from arena.judge.attacks import cluster
from arena.schemas import (
    DiscoveryConfirmation,
    DiscoveryConfirmReport,
    DiscoveryConfirmRequest,
    DiscoveryExport,
    DiscoveryExportRequest,
    DiscoveryExportRow,
    DiscoveryReport,
    DiscoveryRequest,
    DiscoveryVerdict,
    Sample,
)
from arena.target.app import run_episodes
from arena.target.arms import NoDefence
from arena.target.checker import SUCCESS_SIGNALS
from arena.target.ladder import LADDER
from arena.target.suites import TASKS_BY_ID, Case, exposed_tools, placed_world
from arena.target.world import World

_SCHEMA = """
CREATE TABLE IF NOT EXISTS discovery_attacks (
    run_id TEXT NOT NULL,
    round INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    text TEXT NOT NULL,
    claimed_technique TEXT NOT NULL,
    technique TEXT NOT NULL,
    channel TEXT NOT NULL,
    impact_class TEXT NOT NULL,
    task_id TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    trials INTEGER NOT NULL,
    successes INTEGER NOT NULL,
    success_signals TEXT NOT NULL,
    unscorable INTEGER NOT NULL,
    target_refused INTEGER NOT NULL,
    candidate INTEGER NOT NULL,
    public_band TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, round, idx)
)
"""
# One row per candidate and confirmation target. `text_sha256` is the text that was played, so a
# repeat can refuse if the stored candidate has changed since.
_CONFIRM_SCHEMA = """
CREATE TABLE IF NOT EXISTS discovery_confirmations (
    run_id TEXT NOT NULL,
    round INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    target TEXT NOT NULL,
    text_sha256 TEXT NOT NULL,
    trials INTEGER NOT NULL,
    successes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, round, idx, target)
)
"""


def connect(data_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir / "discovery.db", isolation_level=None, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute(_SCHEMA)
    conn.execute(_CONFIRM_SCHEMA)
    return conn


def _attack_texts(rows) -> list[str]:
    return [
        sample.text
        for sample in (Sample.model_validate(row["sample"]) for row in rows)
        if sample.label == "attack"
    ]


def _public_files(data_dir: Path, private_dir: Path) -> list[Path]:
    """Every file the all-public band reads: train, each Judge partition and test."""
    partitions = [data_dir / "partitions" / f"{name}.jsonl" for name in judge_data.MEASURABLE]
    return [private_dir / "train.jsonl", *partitions, data_dir / "test.jsonl"]


@lru_cache(maxsize=4)
def public_pool(data_dir: Path, private_dir: Path) -> tuple[frozenset[str], ...]:
    """The 5-grams of every public attack in the build. Loaded once per Judge process, so the Judge
    must be restarted after a data rebuild."""
    texts = []
    for path in _public_files(data_dir, private_dir):
        if path.exists():
            texts += _attack_texts(judge_data._read_jsonl(path))
    return tuple(novelty.grams(text) for text in texts)


def _public_band(text: str, request: DiscoveryRequest, data_dir: Path) -> novelty.Band:
    """The band against every public attack. Its settings are always the pre-registered DEFAULTS,
    never a run's overrides, and the cut is calibrated on train as the Attacker-side band is."""
    private_dir = private_data_dir()
    live = request.backend == "live"
    missing = [str(p) for p in _public_files(data_dir, private_dir) if not p.exists()]
    if live and missing:
        raise RuntimeError(
            f"Cannot band against every public attack; missing {missing}. Build the data first."
        )
    pool = public_pool(data_dir, private_dir)
    cut = novelty.threshold(
        private_dir / "train.jsonl",
        data_dir / "discovery_novelty.json",
        percentile=DEFAULTS.novelty_percentile,
        sample=DEFAULTS.novelty_calibration_sample,
        seed=DEFAULTS.seed,
        allow_mock=not live,
    )
    return novelty.band(novelty.nearest(novelty.grams(text), pool), cut)


def _status(attack, technique: str) -> str:
    if technique in DEFAULTS.held_out_techniques:
        return "held_out"
    task = TASKS_BY_ID.get(attack.task_id)
    return "played" if task is not None and task.reads == attack.channel else "rejected"


def check(
    request: DiscoveryRequest, context: measure.Context, conn: sqlite3.Connection
) -> DiscoveryReport:
    target = request.target
    if (request.trials, target.key) != (DEFAULTS.discovery_trials, DEFAULTS.discovery_target_key):
        raise ValueError(
            f"Discovery screens at {DEFAULTS.discovery_trials} trials on "
            f"{DEFAULTS.discovery_target_key}, as pre-registered; got {request.trials} on "
            f"{target.key}."
        )
    techniques = [taxonomy.classify(a.text, a.channel) for a in request.attacks]
    statuses = [_status(a, t) for a, t in zip(request.attacks, techniques, strict=True)]

    base = World.build(request.seed)
    case_ids = {}
    cases = []
    for index, (attack, status) in enumerate(zip(request.attacks, statuses, strict=True)):
        if status != "played":
            continue
        task = TASKS_BY_ID[attack.task_id]
        case_id = f"disc-{request.run_id}-r{request.round}-a{index}"
        case_ids[case_id] = index
        cases.append(
            Case(
                case_id,
                task,
                placed_world(base, task, attack.text, target.placements),
                exposed_tools(task, target.tools),
                techniques[index],
                True,
            )
        )
    results = (
        run_episodes(
            cases,
            target=target,
            defence=NoDefence(),
            trials=request.trials,
            cache=context.cache,
            backend=measure._backend(request, context.root),
        )
        if cases
        else []
    )
    by_attack: dict[int, list] = {}
    for result in results:
        by_attack.setdefault(case_ids[result.case_id], []).append(result)

    verdicts = []
    for index, (attack, technique, status) in enumerate(
        zip(request.attacks, techniques, statuses, strict=True)
    ):
        mine = by_attack.get(index, [])
        won = [r for r in mine if r.outcome.attack_succeeded]
        verdicts.append(
            DiscoveryVerdict(
                index=index,
                task_id=attack.task_id,
                technique=technique,
                status=status,
                trials=len(mine),
                successes=len(won),
                success_signals=sorted(
                    {s for r in won for s in r.outcome.signals} & SUCCESS_SIGNALS
                ),
                unscorable=sum(r.ended_unscorable for r in mine),
                target_refused=sum(r.ended_refused for r in mine),
                candidate=len(won) >= DEFAULTS.discovery_candidate_min,
            )
        )
    bands = {
        v.index: _public_band(request.attacks[v.index].text, request, context.data_dir)
        for v in verdicts
        if v.candidate
    }
    _store(conn, request, verdicts, bands)
    return DiscoveryReport(verdicts=verdicts)


def _store(conn, request: DiscoveryRequest, verdicts, bands) -> None:
    stamp = datetime.now(UTC).isoformat(timespec="milliseconds")
    rows = [
        (
            request.run_id,
            request.round,
            v.index,
            attack.text,
            attack.technique,
            v.technique,
            attack.channel,
            attack.impact_class,
            attack.task_id,
            request.target.key,
            v.status,
            v.trials,
            v.successes,
            json.dumps(v.success_signals),
            v.unscorable,
            v.target_refused,
            int(v.candidate),
            bands.get(v.index),
            stamp,
        )
        for v, attack in zip(verdicts, request.attacks, strict=True)
    ]
    conn.execute("BEGIN IMMEDIATE")
    try:
        # A repeat of a round replaces that round's rows and no other, so no attack from an
        # earlier, longer batch lingers.
        conn.execute(
            "DELETE FROM discovery_attacks WHERE run_id = ? AND round = ?",
            (request.run_id, request.round),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO discovery_attacks VALUES"
            " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _confirm_targets():
    """The pre-registered confirmation targets, resolved from the ladder by key."""
    by_key = {spec.key: spec for spec in LADDER}
    missing = [key for key in DEFAULTS.discovery_confirm_keys if key not in by_key]
    if missing:
        raise ValueError(f"Confirmation targets {missing} are not ladder rungs.")
    return [by_key[key] for key in DEFAULTS.discovery_confirm_keys]


def confirm(
    request: DiscoveryConfirmRequest, context: measure.Context, conn: sqlite3.Connection
) -> DiscoveryConfirmReport:
    """Play each of a round's stored candidates on every confirmation target, in its own task, at
    the pinned trials. The texts are read from this database, so nothing new can be confirmed, and
    only `confirmed` goes back: the counts stay here."""
    rows = conn.execute(
        "SELECT idx, text, task_id FROM discovery_attacks"
        " WHERE run_id = ? AND round = ? AND candidate = 1 ORDER BY idx",
        (request.run_id, request.round),
    ).fetchall()
    trials = DEFAULTS.discovery_confirm_trials
    base = World.build(request.seed)
    backend = measure._backend(request, context.root)
    counts: dict[int, dict[str, int]] = {idx: {} for idx, _, _ in rows}
    stored = []
    for target in _confirm_targets():
        cases, index_of, digest_of = [], {}, {}
        for idx, text, task_id in rows:
            digest = hashlib.sha256(text.encode()).hexdigest()
            earlier = conn.execute(
                "SELECT text_sha256 FROM discovery_confirmations"
                " WHERE run_id = ? AND round = ? AND idx = ? AND target = ?",
                (request.run_id, request.round, idx, target.key),
            ).fetchone()
            if earlier is not None and earlier[0] != digest:
                raise ValueError(
                    f"Candidate {idx} of round {request.round} changed after it was confirmed."
                )
            task = TASKS_BY_ID[task_id]
            case_id = f"conf-{request.run_id}-r{request.round}-a{idx}"
            index_of[case_id], digest_of[idx] = idx, digest
            cases.append(
                Case(
                    case_id,
                    task,
                    placed_world(base, task, text, target.placements),
                    exposed_tools(task, target.tools),
                    case_id,
                    True,
                )
            )
        results = (
            run_episodes(
                cases,
                target=target,
                defence=NoDefence(),
                trials=trials,
                cache=context.cache,
                backend=backend,
            )
            if cases
            else []
        )
        for idx in counts:
            counts[idx][target.key] = 0
        for result in results:
            if result.outcome.attack_succeeded:
                counts[index_of[result.case_id]][target.key] += 1
        stored += [
            (request.run_id, request.round, idx, target.key, digest_of[idx], trials,
             counts[idx][target.key])
            for idx in counts
        ]
    stamp = datetime.now(UTC).isoformat(timespec="milliseconds")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.executemany(
            "INSERT OR REPLACE INTO discovery_confirmations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(*row, stamp) for row in stored],
        )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return DiscoveryConfirmReport(
        candidates=[
            DiscoveryConfirmation(
                index=idx,
                confirmed=any(n >= DEFAULTS.discovery_confirm_min for n in by_target.values()),
            )
            for idx, by_target in counts.items()
        ]
    )


def export(request: DiscoveryExportRequest, conn: sqlite3.Connection) -> DiscoveryExport:
    """Every attack of a run with its confirmations and, for candidates, a cluster across rounds.
    For the operator's private findings file only."""
    columns = (
        "round, idx, text, claimed_technique, technique, channel, impact_class, task_id, status,"
        " trials, successes, success_signals, unscorable, target_refused, candidate, public_band"
    )
    rows = conn.execute(
        f"SELECT {columns} FROM discovery_attacks WHERE run_id = ? ORDER BY round, idx",  # noqa: S608
        (request.run_id,),
    ).fetchall()
    confirmations: dict[tuple[int, int], dict[str, int]] = {}
    for round_, idx, target, successes in conn.execute(
        "SELECT round, idx, target, successes FROM discovery_confirmations WHERE run_id = ?",
        (request.run_id,),
    ):
        confirmations.setdefault((round_, idx), {})[target] = successes
    candidates = [row for row in rows if row[14]]
    names = cluster(
        0,
        [row[2] for row in candidates],
        [row[4] for row in candidates],
        DEFAULTS.attack_cluster_jaccard,
    )
    cluster_of = {(row[0], row[1]): name for row, name in zip(candidates, names, strict=True)}
    return DiscoveryExport(
        run_id=request.run_id,
        rows=[
            DiscoveryExportRow(
                round=row[0],
                index=row[1],
                text=row[2],
                claimed_technique=row[3],
                technique=row[4],
                channel=row[5],
                impact_class=row[6],
                task_id=row[7],
                status=row[8],
                trials=row[9],
                successes=row[10],
                success_signals=json.loads(row[11]),
                unscorable=row[12],
                target_refused=row[13],
                candidate=bool(row[14]),
                public_band=row[15],
                cluster=cluster_of.get((row[0], row[1])),
                confirmations=confirmations.get((row[0], row[1]), {}),
            )
            for row in rows
        ],
    )
