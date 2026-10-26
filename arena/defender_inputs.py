"""What the Defender may see, chosen in code on the orchestrator's side (PLAN sections 8 and 10).

- Evasions: this cycle's own batch only, read from its `attack_batch` episode, and only the valid,
  evaded and not held-back attacks. Never the novelty archive, which holds earlier cycles'
  held-back attacks, and never another cycle's batch.
- Train attacks and hard benign cases: from `train` only. A row from any other partition stops
  the read, so dev, calibration and test data cannot reach the Defender through this file.
- Hard benign cases: first the benign rows the incumbent's own rules flag (its false positives),
  then the rows most like the shown evasions, taken in turn from each benign category so every
  category the FPR caps is represented. A rule hit is a fixed score, so this says nothing about
  the calibrated threshold. No model is called.
"""

import json
import random
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from arena import novelty
from arena.agents.defender import ShownEvasion
from arena.config import DEFAULTS, ArenaConfig
from arena.detector.normalisers import normalise
from arena.detector.rules import RuleSet, rule_hits
from arena.memory.memory import Memory
from arena.schemas import DetectorConfig, Sample


class NotTrain(ValueError):
    """The train file holds a row from another partition. Nothing from it is used."""


def shown_evasions(memory: Memory, cycle_id: int) -> tuple[ShownEvasion, ...]:
    batch = memory.episode(cycle_id, "attack_batch")
    if batch is None:
        return ()
    return tuple(
        ShownEvasion(text, verdict["technique"])
        for verdict, text in zip(batch["verdicts"], batch["texts"], strict=True)
        if verdict["valid"]
        and verdict["evaded"]
        and not verdict["held_back"]
        and not verdict["refused"]
    )


def train_samples(path: Path) -> list[Sample]:
    if not path.exists():
        return []
    samples = [
        Sample.model_validate(json.loads(line)["sample"]) for line in path.read_text().splitlines()
    ]
    others = sorted({sample.partition for sample in samples} - {"train"})
    if others:
        raise NotTrain(f"{path} holds rows from {others}; the Defender may only see train.")
    return samples


def _in_class(technique: str, focus: str) -> bool:
    return technique == focus or technique.startswith(focus + ".")


def train_attacks(
    samples: Sequence[Sample], focus: str, count: int, seed: int
) -> tuple[ShownEvasion, ...]:
    """A seeded sample of train attacks in the focus technique class."""
    pool = sorted(
        (s for s in samples if s.label == "attack" and _in_class(s.technique, focus)),
        key=lambda s: s.id,
    )
    # A seeded, repeatable sample, not a secret.
    picked = random.Random(seed).sample(pool, min(count, len(pool)))  # noqa: S311
    return tuple(ShownEvasion(s.text, s.technique) for s in sorted(picked, key=lambda s: s.id))


def hard_benign(
    samples: Sequence[Sample],
    incumbent: DetectorConfig,
    evasions: Sequence[ShownEvasion],
    count: int,
    settings: ArenaConfig = DEFAULTS,
) -> tuple[tuple[str, ...], set[str]]:
    """The chosen benign texts, and the ids of any rules a timeout disabled while choosing."""
    benign = sorted((s for s in samples if s.label == "benign"), key=lambda s: s.id)
    rules = RuleSet(incumbent.rules, settings.regex_timeout_ms / 1000)
    prepared = [normalise(s.text, list(incumbent.normalisers)) for s in benign]
    hits = rule_hits(incumbent, rules, prepared)
    pool = [novelty.grams(e.text) for e in evasions]
    by_category: dict[str, list[tuple[int, float, str, str]]] = defaultdict(list)
    for sample, flagged in zip(benign, hits, strict=True):
        closeness = novelty.nearest(novelty.grams(sample.text), pool)
        by_category[sample.technique].append((-len(flagged), -closeness, sample.id, sample.text))
    queues = [sorted(by_category[name]) for name in sorted(by_category)]
    chosen: list[str] = []
    while len(chosen) < count and any(queues):
        for queue in queues:
            if queue and len(chosen) < count:
                chosen.append(queue.pop(0)[3])
    return tuple(chosen), set(rules.disabled)
