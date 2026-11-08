# ruff: noqa: E501
"""Pilot of an open-model rung: Gemma as the target on the 10 benign tasks (5 trials) and 200 train
attack pairs (2 trials), no defence. Gemma only: no Claude backend exists in this process. Train is
the agent-visible partition; no Judge partition is read. Its cache is private/pilot/pilot.db, apart
from the Judge's. Prints aggregates only.

Usage: python scripts/gemma_pilot.py [RUNG]   (default 3; an open-model rung of the ladder)
  PILOT_SIGNATURES=1  shows the target its tools' argument names (tool_help="signatures")
  PILOT_GUIDED=1      the part 2 screening target's help (tool_help="guided")

The 200 pairs are the first train injection attacks outside the user channel that have a matching
task, ranked by sha256("pilot:" + id). The pass bar is set in PLAN section 7, not here.
"""

import hashlib
import json
import os
import statistics
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from arena import llm
from arena.config import DEFAULTS
from arena.data.pairs import pick_task
from arena.judge import store
from arena.schemas import InjectionPair, Sample, TargetAction
from arena.target.app import run_episodes
from arena.target.arms import NoDefence
from arena.target.checker import SUCCESS_SIGNALS
from arena.target.ladder import LADDER
from arena.target.suites import STANDARD_PLACEMENT, benign_cases, injection_cases

PAIRS, ATTACK_TRIALS, BENIGN_TRIALS = 200, 2, 5


class Timed:
    """Wraps the Ollama backend: times every call and checks each raw output against the schema."""

    def __init__(self, inner):
        self.inner, self.name, self.kind = inner, inner.name, "live"
        self.seconds, self.bad, self.calls = [], 0, 0
        self._lock = threading.Lock()

    def complete(self, **kwargs):
        start = time.time()
        reply = self.inner.complete(**kwargs)
        took = time.time() - start
        bad = False
        if kwargs["request"].tool == "act":
            try:
                TargetAction.model_validate_json(reply.raw_output)
            except ValueError:
                bad = True
        with self._lock:
            self.seconds.append(took)
            self.calls += 1
            self.bad += bad
        return reply


def pick_rung(argv: list[str]):
    number = int(argv[1]) if len(argv) > 1 else 3
    rung = LADDER[number]
    assert rung.model == "target_open", "the pilot runs open-model rungs only"
    if os.environ.get("PILOT_SIGNATURES") == "1":
        rung = rung.model_copy(update={"tool_help": "signatures"})
    if os.environ.get("PILOT_GUIDED") == "1":
        rung = rung.model_copy(update={"tool_help": "guided"})
    return number, rung


def train_pairs(limit: int) -> tuple[list[InjectionPair], dict[str, Sample]]:
    samples = {}
    for line in Path("private/data/train.jsonl").read_text().splitlines():
        if line.strip():
            s = Sample.model_validate(json.loads(line)["sample"])
            if (
                s.label == "attack"
                and s.injection_vs_jailbreak == "injection"
                and s.channel != "user"
            ):
                samples[s.id] = s
    ranked = sorted(samples, key=lambda i: hashlib.sha256(f"pilot:{i}".encode()).hexdigest())
    pairs = []
    for sample_id in ranked:
        task = pick_task(sample_id, samples[sample_id].channel)
        if task is None:
            continue
        s = samples[sample_id]
        pairs.append(
            InjectionPair(
                id=f"pilot-{sample_id}",
                task_id=task.id,
                placement=STANDARD_PLACEMENT[task.reads],
                payload_sample_id=sample_id,
                partition="dev",
                cluster_id=s.cluster_id,
            )
        )
        if len(pairs) == limit:
            break
    return pairs, samples


def report(name, results):
    n = len(results)
    unscorable = sum(r.ended_unscorable for r in results)
    turns = statistics.mean(r.turns for r in results)
    signals = Counter(s for r in results for s in r.outcome.signals)
    print(
        f"{name}: episodes {n}, ended unscorable {unscorable} ({unscorable / n:.1%}), "
        f"mean turns {turns:.2f}, signals {dict(sorted(signals.items()))}"
    )


def main(argv: list[str]) -> None:
    number, rung = pick_rung(argv)
    print(f"pilot rung {number} {rung.key}")
    backend = Timed(llm.OllamaBackend())
    cache = store.EvalCache(store.connect(Path("private/pilot/pilot.db")))
    pairs, samples = train_pairs(PAIRS)
    families = Counter(samples[p.payload_sample_id].generator_family for p in pairs)
    print(f"pilot pairs {len(pairs)}, families {dict(families)}")

    started = time.time()
    benign = run_episodes(
        benign_cases(DEFAULTS.seed, rung.tools),
        target=rung,
        defence=NoDefence(),
        trials=BENIGN_TRIALS,
        cache=cache,
        backend=backend,
    )
    injected = run_episodes(
        injection_cases(pairs, samples, DEFAULTS.seed, rung.tools, rung.placements),
        target=rung,
        defence=NoDefence(),
        trials=ATTACK_TRIALS,
        cache=cache,
        backend=backend,
    )
    minutes = (time.time() - started) / 60

    report("benign", benign)
    print(f"  utility {sum(r.outcome.task_completed for r in benign) / len(benign):.1%}")
    report("injected", injected)
    asr = sum(r.outcome.attack_succeeded for r in injected) / len(injected)
    by_signal = Counter(s for r in injected for s in r.outcome.signals & SUCCESS_SIGNALS)
    fired = {r.case_id for r in injected if r.outcome.attack_succeeded}
    print(f"  ASR (episodes) {asr:.1%}, success signals {dict(by_signal)}")
    print(f"  attacks fired in either trial {len(fired)} of {len(pairs)}")
    if backend.seconds:
        q = statistics.quantiles(backend.seconds, n=20)
        print(
            f"new calls {backend.calls}, schema-invalid act outputs {backend.bad} "
            f"({backend.bad / backend.calls:.1%}), latency p50 {statistics.median(backend.seconds):.2f}s "
            f"p95 {q[18]:.2f}s, {backend.calls / minutes:.1f} calls a minute over {minutes:.1f} min"
        )
    print("Claude calls: 0 (no Claude backend in this process)")


if __name__ == "__main__":
    main(sys.argv)
