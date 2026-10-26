"""Runtime defences around the target model.

A defence decides two things during an episode: what untrusted text the model sees, and which tool
calls go through. The checker never looks at the defence, so every arm is scored by the same rules.

- NoDefence: everything passes.
- DetectorGate: each untrusted segment is scored; a flagged or unscorable segment is replaced by a
  placeholder before the model sees it. Unscorable fails closed: it can only cost utility.
- PlanThenExecute: the model commits to its tool calls (and message recipients) before it sees any
  untrusted text; later calls outside that plan are refused. It may carry a detector gate as well.
  Structural arms have no score, so they are measured on ASR and utility only.
"""

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from arena.schemas import TargetPlan
from arena.target._tools import Segment

WITHHELD = "[content withheld by the safety filter]"

# Scores a batch of texts on the detector's 0 to 100 scale; None means the text was unscorable.
SegmentScorer = Callable[[Sequence[str]], list[float | None]]


class FlagRule(Protocol):
    """Satisfied by arena.judge.stats.Threshold, so the gate applies the measured rule without
    importing the Judge."""

    def flags(self, score: float, tiebreak: float) -> bool: ...


@dataclass(frozen=True)
class NoDefence:
    name: str = "no_defence"


@dataclass(frozen=True)
class DetectorGate:
    scorer: SegmentScorer
    threshold: FlagRule
    seed: int
    name: str = "detector_gate"


@dataclass(frozen=True)
class PlanThenExecute:
    gate: DetectorGate | None = None
    name: str = "plan_then_execute"


Defence = NoDefence | DetectorGate | PlanThenExecute


def gate_of(defence: Defence) -> DetectorGate | None:
    if isinstance(defence, DetectorGate):
        return defence
    if isinstance(defence, PlanThenExecute):
        return defence.gate
    return None


def tiebreak(seed: int, episode: str, segment_id: str) -> float:
    """A seeded uniform draw in [0, 1), the same for the same segment in the same episode."""
    digest = hashlib.sha256(f"{seed}:{episode}:{segment_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def apply_gate(gate: DetectorGate | None, items: Sequence[tuple[str, Segment]]) -> list[Segment]:
    """Gate every untrusted segment of one turn, across all episodes, in one scoring batch.

    `items` pairs each segment with its episode id. Trusted segments pass untouched.
    """
    if gate is None:
        return [segment for _, segment in items]
    untrusted = [index for index, (_, segment) in enumerate(items) if segment.untrusted]
    scores = gate.scorer([items[index][1].text for index in untrusted])
    withheld = set()
    for index, score in zip(untrusted, scores, strict=True):
        episode, segment = items[index]
        if score is None or gate.threshold.flags(score, tiebreak(gate.seed, episode, segment.id)):
            withheld.add(index)
    return [
        Segment(segment.id, WITHHELD, segment.untrusted) if index in withheld else segment
        for index, (_, segment) in enumerate(items)
    ]


def allow_call(defence: Defence, tool: str, args: dict[str, str], plan: TargetPlan | None) -> bool:
    """Plan-then-execute refuses any call the plan did not name, and any message to a recipient
    the plan did not name. Other defences leave tool calls to the exposed tool set."""
    if not isinstance(defence, PlanThenExecute):
        return True
    if plan is None:
        return False
    for step in plan.steps:
        if step.tool != tool:
            continue
        if tool != "send_message" or (step.to or "").lower() == args.get("to", "").lower():
            return True
    return False
