"""Code rules that move lessons and pair predictions with outcomes (PLAN section 9).

The CEO predicts the change in dev end-to-end ASR that its patch will cause. The outcome is the
candidate's ASR minus the incumbent's, read from the Judge's ASR condition: its value is the
candidate's ASR and its limit is the incumbent's plus the configured tolerance. A cycle with no
candidate has no outcome.

A lesson the plan cited is disputed when ASR moved against the prediction by more than the Judge's
ASR confidence-interval half-width, so noise alone never disputes a lesson. A prediction of no
change has no direction and disputes nothing.
"""

from arena.config import ArenaConfig
from arena.memory.memory import Memory
from arena.schemas import JudgeReport


def actual_delta(report: JudgeReport, config: ArenaConfig) -> float | None:
    """Candidate ASR minus incumbent ASR on the dev suite, or None if the Judge measured none."""
    condition = report.conditions.get("asr")
    if condition is None or condition.value is None or condition.limit is None:
        return None
    return condition.value - (condition.limit - config.asr_regression_tolerance)


def noise_band(report: JudgeReport) -> float:
    """Half the width of the candidate's ASR confidence interval."""
    if report.asr is None:
        return 0.0
    return (report.asr.ci_high - report.asr.ci_low) / 2


def contradicts(expected: float, actual: float, band: float) -> bool:
    if expected == 0:
        return False
    return expected * actual < 0 and abs(actual) > band


def dispute_contradicted(
    memory: Memory,
    *,
    cycle_id: int,
    cited: list[int],
    expected: float,
    actual: float,
    band: float,
    step: str,
    role: str,
) -> list[int]:
    """Move each active cited lesson to disputed when the outcome contradicts the prediction."""
    if not contradicts(expected, actual, band):
        return []
    disputed = []
    for lesson_id in sorted(set(cited)):
        row = memory.conn.execute(
            "SELECT status FROM memory_lessons WHERE id = ?", (lesson_id,)
        ).fetchone()
        if row is not None and row[0] == "active":
            memory.set_lesson_status(lesson_id, "disputed", cycle_id=cycle_id, step=step, role=role)
            disputed.append(lesson_id)
    return disputed
