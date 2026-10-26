"""Assigns samples to partitions by group, never by sample (PLAN section 7).

A group is every sample connected through a shared template family or cluster, so near relatives
always land together. Attack and benign groups are split separately. Held-out technique classes and
test-only generator families go to test and nowhere else. Calibration holds benign samples only.
Dev groups alternate between fold 1 and fold 2.
"""

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from arena.config import DEFAULTS, ArenaConfig
from arena.schemas import Sample


@dataclass(frozen=True)
class SplitRow:
    sample: Sample
    fold: int | None


def _groups(samples: Sequence[Sample]) -> list[list[Sample]]:
    parent = list(range(len(samples)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first: dict[tuple[str, str], int] = {}
    for index, sample in enumerate(samples):
        for key in (("family", sample.template_family), ("cluster", sample.cluster_id)):
            if key in first:
                parent[find(index)] = find(first[key])
            else:
                first[key] = index
    grouped: dict[int, list[Sample]] = {}
    for index, sample in enumerate(samples):
        grouped.setdefault(find(index), []).append(sample)
    return list(grouped.values())


def _order(groups: list[list[Sample]], seed: int) -> list[list[Sample]]:
    """A seeded but stable order: the same corpus and seed always split the same way."""

    def key(group: list[Sample]) -> str:
        return hashlib.sha256(f"{seed}:{min(s.id for s in group)}".encode()).hexdigest()

    return sorted(groups, key=key)


def _fill(
    groups: list[list[Sample]], quotas: list[tuple[str, int]], rest: str
) -> list[tuple[str, list[Sample]]]:
    assigned = []
    counts = {name: 0 for name, _ in quotas}
    for group in groups:
        for name, quota in quotas:
            if counts[name] < quota:
                counts[name] += len(group)
                assigned.append((name, group))
                break
        else:
            assigned.append((rest, group))
    return assigned


def split(samples: Sequence[Sample], config: ArenaConfig = DEFAULTS) -> list[SplitRow]:
    def test_only(sample: Sample) -> bool:
        return (
            sample.technique in config.held_out_techniques
            or sample.generator_family in config.test_only_generator_families
        )

    reserved = [s for s in samples if test_only(s)]
    attacks = [s for s in samples if s.label == "attack" and not test_only(s)]
    benign = [s for s in samples if s.label == "benign" and not test_only(s)]

    attack_quotas = [
        ("test", config.test_min_attacks),
        ("dev", config.dev_min_attacks),
        ("monitor", config.monitor_attacks),
        ("ablation_eval", config.ablation_eval_attacks),
    ]
    benign_quotas = [
        ("test", config.test_min_benign),
        ("calibration", config.calibration_min_benign),
        ("dev", config.dev_min_benign),
        ("monitor", config.monitor_benign),
        ("ablation_eval", config.ablation_eval_benign),
    ]
    assigned = _fill(_order(_groups(attacks), config.seed), attack_quotas, "train")
    assigned += _fill(_order(_groups(benign), config.seed), benign_quotas, "train")
    assigned += [("test", group) for group in _groups(reserved)]

    rows = []
    dev_groups = 0
    for partition, group in assigned:
        fold = None
        if partition == "dev":
            fold = 1 + dev_groups % 2
            dev_groups += 1
        rows += [SplitRow(s.model_copy(update={"partition": partition}), fold) for s in group]
    return rows
