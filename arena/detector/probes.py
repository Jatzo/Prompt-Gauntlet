"""Trivial shortcut probes (PLAN section 7).

Each probe scores a sample from one shallow feature, fitted on a training partition. If a probe
gets close to the real detector's TPR, the benchmark rewards the shortcut rather than detection,
and it must be fixed before anything else is trusted.
"""

import math
import re
from collections import Counter
from collections.abc import Callable, Sequence

from arena.schemas import Sample

PROBES = ("length", "language", "punctuation", "source", "template_family", "bag_of_words")

_WORD = re.compile(r"[a-z']+")
_PUNCTUATION = re.compile(r"[^\w\s]")

Probe = Callable[[Sample], float]


def _oriented(feature: Callable[[Sample], float], train: Sequence[Sample]) -> Probe:
    """Point the feature so that higher means more attack-like on the training data."""
    attacks = [feature(s) for s in train if s.label == "attack"]
    benign = [feature(s) for s in train if s.label == "benign"]
    if not attacks or not benign:
        return lambda sample: 0.0
    sign = 1.0 if sum(attacks) / len(attacks) >= sum(benign) / len(benign) else -1.0
    return lambda sample: sign * feature(sample)


def _rate_by(key: Callable[[Sample], str], train: Sequence[Sample]) -> Probe:
    totals, attacks = Counter(), Counter()
    for sample in train:
        totals[key(sample)] += 1
        attacks[key(sample)] += sample.label == "attack"
    prior = sum(attacks.values()) / max(1, sum(totals.values()))

    def score(sample: Sample) -> float:
        seen = totals[key(sample)]
        return attacks[key(sample)] / seen if seen else prior

    return score


def _bag_of_words(train: Sequence[Sample]) -> Probe:
    counts = {"attack": Counter(), "benign": Counter()}
    for sample in train:
        counts[sample.label].update(_WORD.findall(sample.text.lower()))
    vocabulary = set(counts["attack"]) | set(counts["benign"])
    totals = {label: sum(c.values()) + len(vocabulary) for label, c in counts.items()}

    def score(sample: Sample) -> float:
        return sum(
            math.log((counts["attack"][w] + 1) / totals["attack"])
            - math.log((counts["benign"][w] + 1) / totals["benign"])
            for w in _WORD.findall(sample.text.lower())
        )

    return score


def fit_probe(name: str, train: Sequence[Sample]) -> Probe:
    if name == "length":
        return _oriented(lambda s: float(len(s.text)), train)
    if name == "language":
        return _oriented(lambda s: sum(c.isascii() for c in s.text) / max(1, len(s.text)), train)
    if name == "punctuation":
        return _oriented(lambda s: float(len(_PUNCTUATION.findall(s.text))), train)
    if name == "source":
        return _rate_by(lambda s: s.source, train)
    if name == "template_family":
        return _rate_by(lambda s: s.template_family, train)
    if name == "bag_of_words":
        return _bag_of_words(train)
    raise ValueError(f"Unknown probe {name!r}.")
