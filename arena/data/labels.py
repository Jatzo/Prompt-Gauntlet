"""Hand-label queues and audits (PLAN section 7 labelling protocol).

The operator labels blind: a queue holds ids and text only, never the stored label. Scoring an audit
compares the operator's answers with the stored labels and gives the label-error count the
statistics use to widen their intervals.
"""

import hashlib
from collections.abc import Sequence

from arena.judge.stats import LabelNoise
from arena.schemas import Sample


def audit_sample(samples: Sequence[Sample], share: float, seed: int) -> list[Sample]:
    """A seeded random share of a partition, at least one item when the partition is not empty."""
    if not samples:
        return []
    count = max(1, round(share * len(samples)))

    def key(sample: Sample) -> str:
        return hashlib.sha256(f"{seed}:{sample.id}".encode()).hexdigest()

    return sorted(samples, key=key)[:count]


def blind_queue(samples: Sequence[Sample]) -> list[dict]:
    """What the operator sees: id and text only."""
    return [{"id": sample.id, "text": sample.text} for sample in samples]


def score_audit(samples: Sequence[Sample], answers: dict[str, str]) -> LabelNoise:
    """Label errors among the audited items the operator answered."""
    by_id = {sample.id: sample for sample in samples}
    unknown = set(answers) - set(by_id)
    if unknown:
        raise ValueError(f"Answers for ids that were not in the queue: {sorted(unknown)[:5]}")
    bad = [value for value in answers.values() if value not in ("attack", "benign")]
    if bad:
        raise ValueError(f"Answers must be 'attack' or 'benign', not {bad[:3]}")
    errors = sum(by_id[item].label != label for item, label in answers.items())
    return LabelNoise(errors=errors, audited=len(answers))
