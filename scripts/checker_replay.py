"""Replays the checker pass's rung 2 from the Judge's cache and scores it under the current checker.

The checker pass of 27 to 31 October ran under the first success rule, which also counted a call
outside the task's tools. The rule was narrowed on 5 November (PLAN section 6). Rungs 0 and 1 fired
nothing under the old rule, and the new one only removes what the old one counted, so both are 0
under it already. Rung 2 played every paired attack, and its 649 "fired" need scoring again.

Read-only by construction: the cache is opened with SQLite `mode=ro`, so any write fails, and the
backend refuses every call, so a cache miss stops the run instead of reaching a model. It prints
counts only, and the sealed test partition appears only inside the total.

Usage, from the repo root: python scripts/checker_replay.py [JUDGE_DIR]   (default private/judge)
"""

import dataclasses
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path

from arena import baselines
from arena.config import DEFAULTS
from arena.judge import data as judge_data
from arena.judge import measure, store
from arena.target import app
from arena.target.checker import SUCCESS_SIGNALS
from arena.target.ladder import LADDER

RUNG = LADDER[2]
# The checker pass ran at 2 trials a pair.
TRIALS = 2


class CacheOnly:
    """Shaped like the live backend so the cache keys match; it never calls a model."""

    name = "live"
    kind = "live"

    def complete(self, *, role, model_id, step_key, request):
        raise RuntimeError(f"Cache miss for {role} {step_key}. Stopped; no model was called.")


def main(judge_dir: Path) -> int:
    signals: Counter = Counter()
    episodes = 0

    def counting(trace, final_answer, world, task):
        nonlocal episodes
        outcome = checking(trace, final_answer, world, task)
        episodes += 1
        signals.update(outcome.signals)
        return outcome

    checking, app.check = app.check, counting
    measure._backend = lambda request, root: CacheOnly()
    uri = f"file:{(judge_dir / 'judge.db').resolve()}?mode=ro"
    cache = store.EvalCache(sqlite3.connect(uri, uri=True))
    root = Path.cwd()
    context = measure.Context(root, judge_dir, cache)
    request = baselines.request(
        backend="live",
        targets=list(LADDER[:3]),
        reference=LADDER[0],
        trials=TRIALS,
        seed=DEFAULTS.seed,
    )
    base = measure.prepare(request, context)

    fired_by_partition = {}
    pairs_by_partition = {}
    for name, partition in sorted(judge_data.label_partitions(root, judge_dir).items()):
        samples = {row.sample.id: row.sample for row in partition.rows}
        pairs = [pair for pair in partition.pairs if pair.payload_sample_id in samples]
        played = dataclasses.replace(base, samples=samples, dev_pairs=pairs)
        fired_by_partition[name] = len(measure.success_signals(played, RUNG))
        pairs_by_partition[name] = len(pairs)

    checker_commit = subprocess.run(
        ["git", "log", "-1", "--format=%h", "--", "arena/target/checker.py"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    print(f"Rung 2 ({RUNG.key}), {TRIALS} trials, checker at {checker_commit}")
    for name in sorted(fired_by_partition):
        if name != "test":
            print(f"  {name}: {fired_by_partition[name]} of {pairs_by_partition[name]} fired")
    total_fired, total_pairs = sum(fired_by_partition.values()), sum(pairs_by_partition.values())
    print(f"  all partitions, test included: {total_fired} of {total_pairs} fired")
    print(f"  episodes {episodes}")
    success = {key: count for key, count in signals.items() if key in SUCCESS_SIGNALS}
    recorded = {key: count for key, count in signals.items() if key not in SUCCESS_SIGNALS}
    print(f"  success signals, by episode: {dict(sorted(success.items()))}")
    print(f"  recorded, not counted, by episode: {dict(sorted(recorded.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("private/judge")))
