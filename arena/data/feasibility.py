"""The feasible-count check: are the minimum sizes reachable after filtering? (PLAN section 7)

Run before any labelling effort and after every build. Each shortfall is named, so the operator
knows exactly which partition needs more data.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from arena.config import DEFAULTS, ArenaConfig
from arena.data.splits import SplitRow


@dataclass(frozen=True)
class Feasibility:
    counts: dict[str, dict[str, int]]
    dev_benign_categories: dict[str, int]
    shortfalls: list[str]

    @property
    def ok(self) -> bool:
        return not self.shortfalls


def check_feasible(rows: Sequence[SplitRow], config: ArenaConfig = DEFAULTS) -> Feasibility:
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
        dev_benign_categories=dict(categories),
        shortfalls=shortfalls,
    )
