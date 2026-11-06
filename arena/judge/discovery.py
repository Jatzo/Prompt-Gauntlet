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

import json
import sqlite3
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from arena import novelty, taxonomy
from arena.config import DEFAULTS, private_data_dir
from arena.judge import data as judge_data
from arena.judge import measure
from arena.schemas import DiscoveryReport, DiscoveryRequest, DiscoveryVerdict, Sample
from arena.target.app import run_episodes
from arena.target.arms import NoDefence
from arena.target.checker import SUCCESS_SIGNALS
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


def connect(data_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir / "discovery.db", isolation_level=None, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute(_SCHEMA)
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
