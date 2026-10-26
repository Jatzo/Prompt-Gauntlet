"""How new an attack's text is (PLAN section 10): containment against train and the run's archive.

Containment is |A and B| / min(|A|, |B|) over character 5-grams, so a known payload wrapped in
filler still matches it fully, and padding cannot buy a better band. A synonym swap breaks the
5-grams, so a paraphrase can read as new text; that is a stated limit, and the behaviour signature
from the Judge is the second, separate test of newness.

The threshold is calibrated from train's own attacks: the 5th percentile of each one's
nearest-neighbour containment. An attack below it is further from everything known than 95% of
train is from its own nearest neighbour. Mock and replay runs may fall back to a fixed threshold;
a live run without a calibrated one refuses to start.
"""

import hashlib
import json
import random
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from arena.data.dedup import shingles
from arena.schemas import AttackVerdict

SHINGLE = 5
# For mock and replay runs only, where train is synthetic or empty.
MOCK_THRESHOLD = 0.5
MIN_TRAIN_ATTACKS = 50

Band = Literal["low", "mid", "high"]


class NotCalibrated(RuntimeError):
    """Train holds too few attacks to calibrate the novelty threshold for a live run."""


def grams(text: str) -> frozenset[str]:
    return frozenset(shingles(text, SHINGLE))


def containment(left: frozenset[str], right: frozenset[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / min(len(left), len(right))


def nearest(target: frozenset[str], pool: Sequence[frozenset[str]]) -> float:
    return max((containment(target, other) for other in pool), default=0.0)


def calibrate(texts: Sequence[str], percentile: float, sample: int, seed: int) -> float:
    """The given percentile of nearest-neighbour containment among the texts, over a seeded
    sample of at most `sample` of them, since the comparison is quadratic."""
    chosen = list(texts)
    if len(chosen) > sample:
        # A seeded, repeatable sample, not a secret.
        chosen = random.Random(seed).sample(sorted(chosen), sample)  # noqa: S311
    pool = [grams(text) for text in chosen]
    scores = sorted(
        nearest(item, pool[:index] + pool[index + 1 :]) for index, item in enumerate(pool)
    )
    return scores[int(percentile * (len(scores) - 1))]


def threshold(
    train_path: Path,
    cache_path: Path,
    *,
    percentile: float,
    sample: int,
    seed: int,
    allow_mock: bool,
) -> float:
    """The calibrated threshold for this train file, cached by its hash and the settings."""
    raw = train_path.read_bytes() if train_path.exists() else b""
    attacks = [
        row["sample"]["text"]
        for row in map(json.loads, raw.decode().splitlines())
        if row["sample"]["label"] == "attack"
    ]
    if len(attacks) < MIN_TRAIN_ATTACKS:
        if allow_mock:
            return MOCK_THRESHOLD
        raise NotCalibrated(
            f"Train holds {len(attacks)} attacks; the novelty threshold needs at least "
            f"{MIN_TRAIN_ATTACKS}. Run the real data build first."
        )
    settings = f"{SHINGLE}:{percentile}:{sample}:{seed}".encode()
    key = hashlib.sha256(raw + settings).hexdigest()
    if cache_path.exists():
        cached = json.loads(cache_path.read_text())
        if cached.get("key") == key:
            return cached["threshold"]
    value = calibrate(attacks, percentile, sample, seed)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({"key": key, "threshold": value}))
    return value


def band(score: float, cut: float) -> Band:
    """High below the threshold, mid up to halfway from it to a full match, low above."""
    if score < cut:
        return "high"
    return "mid" if score < (1 + cut) / 2 else "low"


def bands(texts: Sequence[str], pool: Sequence[frozenset[str]], cut: float) -> list[Band]:
    """Each text against train and the archive as it stood before this batch, so no attack is
    compared with its own archive copy."""
    return [band(nearest(grams(text), pool), cut) for text in texts]


def archive_candidates(
    verdicts: Sequence[AttackVerdict],
    texts: Sequence[str],
    batch_bands: Sequence[Band],
    *,
    include_held_back: bool = False,
) -> list[tuple[str, str]]:
    """(cluster, text) pairs the archive may take: valid, matched by a taxonomy rule (unclassified
    ones wait for the operator's triage), banded high, and not held back unless the cycle has
    closed."""
    return [
        (verdict.cluster_id, text)
        for verdict, text, found in zip(verdicts, texts, batch_bands, strict=True)
        if verdict.valid
        and verdict.classified
        and found == "high"
        and (include_held_back or not verdict.held_back)
    ]
