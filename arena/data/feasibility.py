"""The feasible-count check: are the minimum sizes reachable after filtering? (PLAN section 7)

Run before any labelling effort and after every build. Each shortfall is named, so the operator
knows exactly which partition needs more data. Notes do not block a build; they show what a
reader of the results needs to know: thin technique classes in train, each partition's channel and
family mix, and how close any test attack comes to a train attack.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from arena.config import DEFAULTS, ArenaConfig
from arena.data.splits import SplitRow
from arena.novelty import MIN_TRAIN_ATTACKS, grams, nearest


@dataclass(frozen=True)
class Feasibility:
    counts: dict[str, dict[str, int]]
    shortfalls: list[str]
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.shortfalls


def check_feasible(
    rows: Sequence[SplitRow], config: ArenaConfig = DEFAULTS, dropped: int = 0
) -> Feasibility:
    """`dropped` is how many samples the split left out (held-out members of a large family)."""
    counts: dict[str, Counter] = {}
    categories: Counter = Counter()
    for row in rows:
        counts.setdefault(row.sample.partition, Counter())[row.sample.label] += 1
        if row.sample.partition == "dev" and row.sample.label == "benign":
            categories[row.sample.technique] += 1

    def have(partition: str, label: str) -> int:
        return counts.get(partition, Counter())[label]

    needs = [
        ("dev", "attack", config.dev_min_attacks),
        ("dev", "benign", config.dev_min_benign),
        ("calibration", "benign", config.calibration_min_benign),
        ("test", "attack", config.test_min_attacks),
        ("test", "benign", config.test_min_benign),
        ("monitor", "attack", config.monitor_attacks),
        ("monitor", "benign", config.monitor_benign),
        ("ablation_eval", "attack", config.ablation_eval_attacks),
        ("ablation_eval", "benign", config.ablation_eval_benign),
        # The novelty threshold will not calibrate below its own minimum, whatever the config says.
        ("train", "attack", max(config.train_min_attacks, MIN_TRAIN_ATTACKS)),
    ]
    shortfalls = [
        f"{partition} has {have(partition, label)} {label} samples, needs {minimum}"
        for partition, label, minimum in needs
        if have(partition, label) < minimum
    ]
    shortfalls += [
        f"dev benign category {category} has {count}, needs {config.min_per_benign_category}"
        for category, count in sorted(categories.items())
        if count < config.min_per_benign_category
    ]
    if have("calibration", "attack"):
        shortfalls.append("calibration holds attack samples; it must be benign only")
    return Feasibility(
        counts={name: dict(counter) for name, counter in counts.items()},
        shortfalls=shortfalls,
        notes=_notes(rows, config)
        + (
            [
                f"{dropped} held-out attacks were dropped: they belong to a family too large for "
                "evaluation, which goes to train, so they could not be held out cleanly."
            ]
            if dropped
            else []
        ),
    )


def _notes(rows: Sequence[SplitRow], config: ArenaConfig) -> list[str]:
    attacks = [row.sample for row in rows if row.sample.label == "attack"]
    train = [sample for sample in attacks if sample.partition == "train"]
    notes = []
    in_train = Counter(sample.technique for sample in train)
    thin = sorted(
        (technique, in_train[technique])
        for technique in {sample.technique for sample in attacks}
        if technique not in config.held_out_techniques
        and in_train[technique] < config.defender_train_attacks
    )
    if thin:
        notes.append(
            f"Technique classes with fewer than {config.defender_train_attacks} train attacks for "
            "the Defender: " + ", ".join(f"{technique} {count}" for technique, count in thin)
        )
    for partition in sorted({sample.partition for sample in attacks}):
        held = [sample for sample in attacks if sample.partition == partition]
        channels = Counter(sample.channel for sample in held)
        families = Counter(sample.generator_family for sample in held)
        notes.append(
            f"{partition} attacks by channel: "
            + ", ".join(f"{name} {count}" for name, count in channels.most_common())
            + "; by family: "
            + ", ".join(f"{name} {count}" for name, count in families.most_common())
        )
    test = [sample for sample in attacks if sample.partition == "test"]
    if train and test:
        pool = [grams(sample.text) for sample in train]
        closest = max(nearest(grams(sample.text), pool) for sample in test)
        notes.append(
            f"Closest any test attack comes to a train attack (5-gram containment): {closest:.2f}"
        )
    return notes
