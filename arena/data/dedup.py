"""Exact and near-duplicate removal, so no near-copy of a sample sits in two partitions.

Near-duplicates are pairs with Jaccard similarity at or above the threshold on character 5-gram
shingles, or cosine similarity at or above the threshold on a hashed n-gram embedding. Only pairs
from different groups count: samples sharing a template family or cluster are meant to be near
relatives, and the split keeps each group whole, so they can never straddle two partitions.
Candidate pairs come from MinHash banding, so the check stays near-linear in corpus size. The
embedding is a non-semantic placeholder until the operator picks a model; it is behind one function
so a real model can replace it.
"""

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from arena.config import DEFAULTS, ArenaConfig
from arena.schemas import Sample

_SPACE = re.compile(r"\s+")
# 64 hashes only pick candidates (standard error about 0.06); the exact Jaccard then decides.
# 16 bands of 4 rows make pairs from about Jaccard 0.5 candidates, well below the 0.8 threshold,
# so few true near-duplicates are missed.
_PERMUTATIONS = 64
_BANDS = 16
_PRIME = (1 << 61) - 1


@dataclass(frozen=True)
class DedupReport:
    kept: list[Sample]
    exact_removed: int
    near_removed: int


def _normal(text: str) -> str:
    return _SPACE.sub(" ", text.lower()).strip()


def shingles(text: str, size: int) -> set[str]:
    text = _normal(text)
    if len(text) <= size:
        return {text}
    return {text[i : i + size] for i in range(len(text) - size + 1)}


def jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left | right else 1.0


def embed(text: str, dimensions: int = 256) -> np.ndarray:
    """Hashed character 3-gram counts, unit length. Not semantic: a placeholder embedder."""
    vector = np.zeros(dimensions)
    for gram in shingles(text, 3):
        vector[
            int(hashlib.md5(gram.encode(), usedforsecurity=False).hexdigest(), 16) % dimensions
        ] += 1
    norm = np.linalg.norm(vector)
    return vector / norm if norm else vector


def _minhash(grams: set[str], coefficients: np.ndarray) -> np.ndarray:
    values = np.array(
        [int(hashlib.md5(g.encode(), usedforsecurity=False).hexdigest()[:15], 16) for g in grams],
        dtype=np.uint64,
    )
    a, b = coefficients
    return ((np.outer(a, values) + b[:, None]) % _PRIME).min(axis=1)


def _same_group(left: Sample, right: Sample) -> bool:
    return left.template_family == right.template_family or left.cluster_id == right.cluster_id


def deduplicate(samples: Sequence[Sample], config: ArenaConfig = DEFAULTS) -> DedupReport:
    """Keep the first of each exact or near-duplicate group, in input order."""
    seen: set[str] = set()
    unique = []
    for sample in samples:
        key = _normal(sample.text)
        if key not in seen:
            seen.add(key)
            unique.append(sample)
    exact_removed = len(samples) - len(unique)

    rng = np.random.default_rng(config.seed)
    coefficients = rng.integers(1, _PRIME, size=(2, _PERMUTATIONS), dtype=np.uint64)
    grams = [shingles(sample.text, config.near_duplicate_shingle_size) for sample in unique]
    vectors = [embed(sample.text) for sample in unique]
    rows = _PERMUTATIONS // _BANDS
    buckets: dict[tuple, list[int]] = {}
    removed: set[int] = set()
    for index, sample_grams in enumerate(grams):
        signature = _minhash(sample_grams, coefficients)
        candidates = set()
        for band in range(_BANDS):
            key = (band, *signature[band * rows : (band + 1) * rows].tolist())
            candidates.update(buckets.setdefault(key, []))
            buckets[key].append(index)
        for other in sorted(candidates):
            if other in removed or _same_group(unique[index], unique[other]):
                continue
            similar = jaccard(sample_grams, grams[other]) >= config.near_duplicate_jaccard
            if similar or float(vectors[index] @ vectors[other]) >= config.near_duplicate_cosine:
                removed.add(index)
                break
    kept = [sample for index, sample in enumerate(unique) if index not in removed]
    return DedupReport(kept=kept, exact_removed=exact_removed, near_removed=len(removed))
