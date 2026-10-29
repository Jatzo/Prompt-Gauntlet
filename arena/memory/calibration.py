"""The CEO's prediction record: (predicted, actual) pairs and a short summary (PLAN section 9).

Only committed cycles count; a rolled-back cycle's prediction is left out, as its lessons are. The
summary enters the briefing only once `calibration_feedback_min_pairs` pairs exist, so a handful of
noisy cycles cannot steer the CEO.
"""

import sqlite3
from dataclasses import dataclass

from arena.config import ArenaConfig


@dataclass(frozen=True)
class Pair:
    cycle_id: int
    expected: float
    actual: float
    confidence: float


def pairs(conn: sqlite3.Connection, run_id: str) -> list[Pair]:
    rows = conn.execute(
        "SELECT p.cycle_id, p.expected_delta, p.actual_delta, p.confidence"
        " FROM memory_predictions p JOIN cycles c ON c.id = p.cycle_id"
        " WHERE c.run_id = ? AND c.state = 'committed' AND p.actual_delta IS NOT NULL"
        " ORDER BY p.cycle_id",
        (run_id,),
    ).fetchall()
    return [Pair(*row) for row in rows]


def summary(found: list[Pair], config: ArenaConfig) -> str | None:
    """A few lines on how the predictions have held up, or None below the threshold."""
    if len(found) < config.calibration_feedback_min_pairs:
        return None
    errors = [pair.actual - pair.expected for pair in found]
    same = sum(pair.expected * pair.actual > 0 for pair in found)
    lines = [
        f"{len(found)} predictions with outcomes. Mean error (actual minus predicted): "
        f"{sum(errors) / len(errors):+.3f}.",
        f"Direction right in {same} of {len(found)}.",
    ]
    for low, high, name in ((0.0, 0.5, "below 0.5"), (0.5, 1.01, "0.5 and above")):
        bucket = [pair for pair in found if low <= pair.confidence < high]
        if bucket:
            right = sum(pair.expected * pair.actual > 0 for pair in bucket)
            lines.append(f"Confidence {name}: direction right in {right} of {len(bucket)}.")
    return "\n".join(lines)
