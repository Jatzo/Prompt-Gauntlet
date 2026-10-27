"""Assigns samples to partitions by group, never by sample (PLAN section 7).

A group is every sample connected through a shared template family or cluster, so near relatives
always land together. Two attacks also join one group when the shorter has most of its 5-grams in
the longer: a short payload repeated inside a long email is the same attack, even though the two
texts are too different in length to count as near-duplicates. Attack and benign groups are split
separately. A group holding any held-out technique or test-only generator family goes to test
whole and nowhere else. An attack group too large to be one evaluation item among many (one
family repeated hundreds of times) goes to train whole, so the evaluation partitions measure many
distinct attacks. Calibration holds benign samples only. Dev groups alternate between fold 1 and
fold 2.

Attacks fill test, dev, train (up to its minimum), ablation_eval, then monitor, and the rest go to
train: the partitions behind the headline and the keep rule fill first, and train always gets the
attacks the novelty threshold and the Defender need. Attack groups are interleaved by channel in
proportion to supply, so every partition holds about the same channel mix. Benign quotas fill a
margin over their minimum, because contested items are removed after labelling. Attack quotas need
none: an attack keeps its source label, so labelling never removes one.
"""

import hashlib
import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from arena.config import DEFAULTS, ArenaConfig
from arena.novelty import containment, grams
from arena.schemas import Sample

# Each text's 16 lowest-hashing 5-grams pick containment candidates; a candidate must hold 10 of
# them. A pair at exactly 0.8 containment is found about 97 times in 100, more often above it, and
# a short text (under 40 grams) at 0.8 is almost never missed, since its few absent grams rarely
# all fall in the sketch.
_SKETCH = 16
_SKETCH_HITS = 10
# A text this short (about 24 characters) is too generic to link anything: one stock phrase found
# inside many emails would chain unrelated families into one group. It also keeps every sketch full.
_MIN_LINK_GRAMS = 20


@dataclass(frozen=True)
class SplitRow:
    sample: Sample
    fold: int | None


def _contained_pairs(samples: Sequence[Sample], cut: float) -> list[tuple[int, int]]:
    """Index pairs where the shorter text has at least `cut` of its 5-grams in the longer.

    Candidates come from a small sketch of each text in an inverted index, so the check stays
    near-linear in corpus size; the exact containment then decides. The hash is stable, so the same
    corpus always gives the same pairs.
    """
    sets = [grams(sample.text) for sample in samples]

    def rank(gram: str) -> str:
        return hashlib.blake2b(gram.encode(), digest_size=8).hexdigest()

    sketches = [sorted(found, key=rank)[:_SKETCH] for found in sets]
    wanted = {gram for sketch in sketches for gram in sketch}
    holders: dict[str, list[int]] = {}
    for index, found in enumerate(sets):
        for gram in found & wanted:
            holders.setdefault(gram, []).append(index)
    pairs = []
    for index, sketch in enumerate(sketches):
        if len(sets[index]) < _MIN_LINK_GRAMS:
            continue
        hits = Counter(other for gram in sketch for other in holders[gram] if other != index)
        for other, count in hits.items():
            if count < _SKETCH_HITS or len(sets[other]) < _MIN_LINK_GRAMS:
                continue
            if containment(sets[index], sets[other]) >= cut:
                pairs.append((index, other))
    return pairs


def _groups(
    samples: Sequence[Sample], linked: Sequence[tuple[int, int]] = ()
) -> list[list[Sample]]:
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
    for left, right in linked:
        parent[find(left)] = find(right)
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


def _interleave(groups: list[list[Sample]]) -> list[list[Sample]]:
    """Mix the channels evenly through the order, keeping each channel's own seeded order.

    Each group is placed at the midpoint of its share of its channel's samples, so any run of the
    result holds about the overall channel mix, and filling quotas in order gives every partition
    that mix without splitting a group.
    """
    by_channel: dict[str, list[list[Sample]]] = {}
    for group in groups:
        channel = Counter(sample.channel for sample in group).most_common(1)[0][0]
        by_channel.setdefault(channel, []).append(group)
    placed = []
    for channel, found in by_channel.items():
        total, before = sum(map(len, found)), 0
        for group in found:
            placed.append(((before + len(group) / 2) / total, channel, group))
            before += len(group)
    return [group for _, _, group in sorted(placed, key=lambda item: item[:2])]


def split(samples: Sequence[Sample], config: ArenaConfig = DEFAULTS) -> list[SplitRow]:
    def test_only(sample: Sample) -> bool:
        return (
            sample.technique in config.held_out_techniques
            or sample.generator_family in config.test_only_generator_families
        )

    attacks = [s for s in samples if s.label == "attack"]
    benign = [s for s in samples if s.label == "benign"]
    linked = _groups(attacks, _contained_pairs(attacks, config.attack_containment_group))

    # A large family goes to train even if a few of its members are held out: those members are
    # dropped, because in test their near-copies would sit in train, and the whole family in test
    # would swamp it. The build reports how many were dropped. A large family made only of held-out
    # or test-only members has nothing to send to train, so it goes to test whole like any other.
    def too_large(group: list[Sample]) -> bool:
        return len(group) > config.attack_group_train_only_above and not all(
            test_only(s) for s in group
        )

    large = [[s for s in group if not test_only(s)] for group in linked if too_large(group)]
    reserved, attack_groups, benign_groups = [], [], []
    for groups, kept in (
        ([g for g in linked if not too_large(g)], attack_groups),
        (_groups(benign), benign_groups),
    ):
        for group in groups:
            (reserved if any(test_only(s) for s in group) else kept).append(group)

    attack_quotas = [
        ("test", config.test_min_attacks),
        ("dev", config.dev_min_attacks),
        # On top of the large families, so the Defender sees every channel and many techniques.
        ("train", config.train_min_attacks),
        ("ablation_eval", config.ablation_eval_attacks),
        ("monitor", config.monitor_attacks),
    ]

    def with_margin(minimum: int) -> int:
        return math.ceil(minimum * (1 + config.benign_quota_margin))

    benign_quotas = [
        ("test", with_margin(config.test_min_benign)),
        ("calibration", with_margin(config.calibration_min_benign)),
        ("dev", with_margin(config.dev_min_benign)),
        ("monitor", with_margin(config.monitor_benign)),
        ("ablation_eval", with_margin(config.ablation_eval_benign)),
    ]
    assigned = [("train", group) for group in _order(large, config.seed)]
    assigned += _fill(_interleave(_order(attack_groups, config.seed)), attack_quotas, "train")
    assigned += _fill(_order(benign_groups, config.seed), benign_quotas, "train")
    assigned += [("test", group) for group in reserved]

    rows = []
    dev_groups = 0
    for partition, group in assigned:
        fold = None
        if partition == "dev":
            fold = 1 + dev_groups % 2
            dev_groups += 1
        rows += [SplitRow(s.model_copy(update={"partition": partition}), fold) for s in group]
    return rows
