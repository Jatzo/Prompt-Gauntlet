"""The baseline-ASR gate and its pre-decided fallback ladder (PLAN section 7).

A pure function of the no-defence ASR measured on each rung, so anyone can recompute it from a saved
report. The ladder is data, in the plan's order; rung 3 (a deliberately weak open model) is out of
Phase 2, so an exhausted ladder means the claim is narrowed.
"""

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Literal

from arena.config import ArenaConfig
from arena.schemas import Metric, TargetSpec

LADDER: tuple[TargetSpec, ...] = (
    TargetSpec(model="target_strong"),
    # (1) a weaker target model
    TargetSpec(model="target_weak"),
    # (2) a more permissive tool policy and riskier placements
    TargetSpec(model="target_weak", tools="permissive", placements="risky"),
)


@dataclass(frozen=True)
class GateDecision:
    status: Literal["pass", "fallback_pass", "needs_operator", "narrowed", "measure_next"]
    rung: int | None
    reason: str


def decide(
    no_defence_asr: dict[str, Metric],
    config: ArenaConfig,
    *,
    first_ladder_run: date | None,
    today: date,
) -> GateDecision:
    """`no_defence_asr` maps a rung's key to its measured ASR; rungs not yet measured are absent.

    The point estimate decides; the interval is reported beside it.
    """
    low, high = config.baseline_asr_low, config.baseline_asr_high
    first = no_defence_asr.get(LADDER[0].key)
    if first is None:
        return GateDecision("measure_next", 0, "The evaluation target has not been measured.")
    if low <= first.value <= high:
        return GateDecision("pass", 0, f"ASR {first.value:.2f} is inside [{low}, {high}].")
    if first.value >= config.baseline_asr_fallback_below:
        return GateDecision(
            "needs_operator",
            0,
            f"ASR {first.value:.2f} is outside [{low}, {high}] but not below "
            f"{config.baseline_asr_fallback_below}, which the fallback ladder does not cover.",
        )

    # The cut-off stops the search for a new rung; a rung already measured as passing still passes.
    cutoff = config.ladder_cutoff_days
    expired = first_ladder_run is not None and today - first_ladder_run > timedelta(days=cutoff)
    for rung, spec in enumerate(LADDER[1:], start=1):
        measured = no_defence_asr.get(spec.key)
        if measured is None and expired:
            return GateDecision(
                "narrowed",
                None,
                f"The ladder has run for more than {cutoff} days without a usable baseline. "
                "Narrow the claim to relative improvement on an engineered target.",
            )
        if measured is None:
            return GateDecision("measure_next", rung, f"Measure rung {rung} ({spec.key}) next.")
        if low <= measured.value <= high:
            return GateDecision(
                "fallback_pass", rung, f"Rung {rung} ({spec.key}) has ASR {measured.value:.2f}."
            )
    return GateDecision(
        "narrowed",
        None,
        "No rung of the ladder gave a usable baseline. "
        "Narrow the claim to relative improvement on an engineered target.",
    )
