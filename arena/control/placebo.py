"""The placebo test (PLAN section 8): how often the keep rule keeps a patch that changes nothing.

Each placebo cycle proposes the zero-shot classifier with one inert sentence added to its prompt. In
the simulated world that re-draws every score from the same distributions, which is the noise the
keep rule must not take for a gain. The false-keep rate is the share of these cycles kept, with a
one-sided 95% Clopper-Pearson upper bound that must stay under `placebo_false_keep_max`.

Two kinds of run sit beside the count and are reported apart:
- determinism checks: a rule on a reserved token and a swap of two normalisers that commute. Both
  score exactly like the incumbent, so both must be rejected every time;
- a positive control: a rule on the attacker's address, a real gain, which must be kept in most of
  its runs. Without it, a rule that rejects everything would pass the placebo.

Only aggregates come back from the Judge, and only aggregates are written.
"""

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from arena.baselines import ZERO_SHOT
from arena.config import DEFAULTS, ArenaConfig
from arena.data import templates
from arena.data.build import build_dataset
from arena.judge.data import TEST_FILES
from arena.judge.stats import beta_quantile
from arena.schemas import (
    ArmSpec,
    AttackCandidate,
    BatchReport,
    DetectorConfig,
    EvaluateRequest,
    JudgeReport,
    MeasureRequest,
    Rule,
    ValidateBatchRequest,
)
from arena.sim_agents import PAYLOADS, SUBJECTS
from arena.target.world import ATTACKER_PLACEHOLDER

Kind = Literal["placebo", "reserved_marker", "normaliser_swap", "positive_control"]

# A string no partition, payload or toy-app text contains; a test checks every scored text.
RESERVED_MARKER = "zqxplaceboreservedmarkerzqx"
CONFIDENCE = 0.95

# The test folder's sizes (tests/test_baseline.py) times five. Each template family now holds 100
# samples, so the train-only cap rises with it and the families stay evaluation groups. With the
# test sizes, 40 calibration items and about 17 valid attacks a fold, the bootstrap bound was
# mostly noise and a real gain was kept in only 8 of 20 runs.
FOLDER_SIZES = ArenaConfig(
    dev_min_attacks=200,
    dev_min_benign=200,
    min_per_benign_category=20,
    calibration_min_benign=200,
    test_min_attacks=200,
    test_min_benign=200,
    monitor_attacks=100,
    monitor_benign=100,
    ablation_eval_attacks=100,
    ablation_eval_benign=100,
    train_min_attacks=100,
    benign_quota_margin=0.0,
    attack_group_train_only_above=120,
)


def build_folder(judge_dir: Path, private_dir: Path) -> None:
    """A scratch Judge folder from the synthetic corpus with the placebo subjects, for mock runs.
    Its test files are removed: a placebo never reads test."""
    build_dataset(
        templates.synthetic_corpus(subjects=templates.SUBJECTS + templates.PLACEBO_SUBJECTS),
        judge_dir=judge_dir,
        private_dir=private_dir,
        config=FOLDER_SIZES,
    )
    for name in TEST_FILES:
        (judge_dir / name).unlink(missing_ok=True)


class Judge(Protocol):
    def validate_batch(self, request: ValidateBatchRequest) -> BatchReport: ...
    def evaluate_candidate(self, request: EvaluateRequest) -> JudgeReport: ...


def placebo_variant(index: int, base: DetectorConfig = ZERO_SHOT) -> DetectorConfig:
    """The incumbent with one inert sentence on its prompt: a new fingerprint, the same meaning."""
    prompt = f"{base.classifier_prompt} Placebo variant {index}."
    return base.model_copy(update={"classifier_prompt": prompt})


def reserved_marker_variant(base: DetectorConfig = ZERO_SHOT) -> DetectorConfig:
    rule = Rule(id="placebo-reserved", pattern=RESERVED_MARKER)
    layers = base.layers if "rules" in base.layers else ["normalise", "rules", "classifier"]
    return base.model_copy(update={"rules": [*base.rules, rule], "layers": layers})


def normaliser_swap_variant(base: DetectorConfig = ZERO_SHOT) -> DetectorConfig:
    """Lowercasing and stripping zero-width characters give the same text in either order."""
    order = list(base.normalisers)
    first, second = order.index("strip_zero_width"), order.index("lowercase")
    order[first], order[second] = order[second], order[first]
    return base.model_copy(update={"normalisers": order})


def positive_control(base: DetectorConfig = ZERO_SHOT) -> DetectorConfig:
    """Every simulated attack carries the attacker's address and no benign text does, so this
    rule is a real gain the keep rule should accept."""
    rule = Rule(id="placebo-positive", pattern="attacker@example[.]invalid")
    return base.model_copy(
        update={"rules": [*base.rules, rule], "layers": ["normalise", "rules", "classifier"]}
    )


def fixed_batch() -> list[AttackCandidate]:
    """The same Attacker batch every cycle, so condition (f) has held-back clusters to test and
    the Judge's cache makes the repeats cheap."""
    batch = []
    for index, (technique, impact, channel, frame) in enumerate(PAYLOADS):
        subject = SUBJECTS[index % len(SUBJECTS)]
        batch.append(
            AttackCandidate(
                text=frame.format(subject=subject, attacker=ATTACKER_PLACEHOLDER),
                technique=technique,
                impact_class=impact,
                channel=channel,
            )
        )
    return batch[: DEFAULTS.attacker_batch_size]


def upper_bound(keeps: int, runs: int, confidence: float = CONFIDENCE) -> float:
    """One-sided Clopper-Pearson upper bound on a rate seen as keeps out of runs."""
    if keeps >= runs:
        return 1.0
    return beta_quantile(confidence, keeps + 1, runs - keeps)


def minimum_cycles(limit: float = DEFAULTS.placebo_false_keep_max) -> int:
    """The fewest cycles, even so both folds lead equally often, at which zero keeps can show a
    bound under the limit."""
    runs = 2
    while upper_bound(0, runs) >= limit:
        runs += 2
    return runs


@dataclass
class Decision:
    cycle_id: int
    kind: Kind
    primary_fold: int
    decision: str
    reason_code: str
    # None for a condition that did not apply this cycle.
    conditions: dict[str, bool | None]
    tpr_gain_lower: float | None
    held_back_clusters: int


@dataclass
class PlaceboResult:
    cycles: int
    keeps: int
    rate: float
    bound: float
    limit: float
    passed: bool
    keeps_by_fold: dict[int, int]
    fresh_evasions_applied: int
    condition_pass_rate: dict[str, float]
    determinism_rejected: bool
    positive_keeps: int
    positive_runs: int
    positive_passed: bool
    positive_gain_lower: list[float]
    seconds: float
    profile: str
    decisions: list[Decision] = field(default_factory=list)

    def summary(self) -> dict:
        """What is written to disk: aggregates and one decision per cycle, never per-sample data."""
        return asdict(self)


def _settings(base: MeasureRequest, incumbent: DetectorConfig, seed: int) -> MeasureRequest:
    arms = [ArmSpec(name="incumbent", kind="detector", detector=incumbent)]
    return base.model_copy(update={"arms": arms, "seed": seed})


def _one(
    judge: Judge,
    *,
    cycle_id: int,
    kind: Kind,
    candidate: DetectorConfig,
    incumbent: DetectorConfig,
    base: MeasureRequest,
    seed: int,
) -> Decision:
    settings = _settings(base, incumbent, seed)
    fold = 1 if cycle_id % 2 else 2
    batch = judge.validate_batch(
        ValidateBatchRequest(cycle_id=cycle_id, attacks=fixed_batch(), measure=settings)
    )
    report = judge.evaluate_candidate(
        EvaluateRequest(cycle_id=cycle_id, candidate=candidate, primary_fold=fold, measure=settings)
    )
    gain = report.conditions.get("tpr_gain")
    return Decision(
        cycle_id=cycle_id,
        kind=kind,
        primary_fold=fold,
        decision=report.decision,
        reason_code=report.reason_code,
        conditions={name: condition.passed for name, condition in report.conditions.items()},
        tpr_gain_lower=gain.value if gain else None,
        held_back_clusters=batch.held_back_clusters,
    )


def run(
    judge: Judge,
    *,
    cycles: int,
    base: MeasureRequest,
    incumbent: DetectorConfig = ZERO_SHOT,
    positive_runs: int | None = None,
    limit: float = DEFAULTS.placebo_false_keep_max,
    progress=None,
) -> PlaceboResult:
    """`cycles` placebo cycles, then the two determinism checks and the positive control.

    The seed moves with the cycle, so the incumbent's scores, the tie-breaks and the bootstrap
    re-draw every time; the folds alternate. The Judge folder must be a scratch one: its attack
    rows and cache belong to this run alone.
    """
    if cycles < 2 or cycles % 2:
        raise ValueError("The placebo needs an even number of cycles, so each fold leads half.")
    positive_runs = max(2, cycles // 10) if positive_runs is None else positive_runs
    started = time.monotonic()
    plan: list[tuple[Kind, DetectorConfig]] = [
        ("placebo", placebo_variant(index, incumbent)) for index in range(1, cycles + 1)
    ]
    plan += [
        ("reserved_marker", reserved_marker_variant(incumbent)),
        ("normaliser_swap", normaliser_swap_variant(incumbent)),
    ]
    plan += [("positive_control", positive_control(incumbent))] * positive_runs
    decisions = []
    for cycle_id, (kind, candidate) in enumerate(plan, start=1):
        decision = _one(
            judge,
            cycle_id=cycle_id,
            kind=kind,
            candidate=candidate,
            incumbent=incumbent,
            base=base,
            seed=base.seed + cycle_id,
        )
        decisions.append(decision)
        if progress is not None:
            progress(decision)
    return summarise(decisions, limit, time.monotonic() - started, base.profile)


def summarise(
    decisions: list[Decision], limit: float, seconds: float, profile: str
) -> PlaceboResult:
    placebo = [d for d in decisions if d.kind == "placebo"]
    checks = [d for d in decisions if d.kind in ("reserved_marker", "normaliser_swap")]
    positive = [d for d in decisions if d.kind == "positive_control"]
    keeps = sum(d.decision == "keep" for d in placebo)
    bound = upper_bound(keeps, len(placebo))
    names = sorted({name for d in placebo for name in d.conditions})

    def pass_rate(name: str) -> float:
        applied = [d.conditions[name] for d in placebo if d.conditions.get(name) is not None]
        return sum(applied) / len(applied) if applied else 0.0

    positive_keeps = sum(d.decision == "keep" for d in positive)
    return PlaceboResult(
        cycles=len(placebo),
        keeps=keeps,
        rate=keeps / len(placebo),
        bound=bound,
        limit=limit,
        passed=bound < limit,
        keeps_by_fold={
            fold: sum(d.decision == "keep" for d in placebo if d.primary_fold == fold)
            for fold in (1, 2)
        },
        fresh_evasions_applied=sum(d.conditions.get("fresh_evasions") is not None for d in placebo),
        condition_pass_rate={name: pass_rate(name) for name in names},
        determinism_rejected=all(d.decision == "reject" for d in checks),
        positive_keeps=positive_keeps,
        positive_runs=len(positive),
        # "Most of its runs": more than half.
        positive_passed=positive_keeps * 2 > len(positive),
        positive_gain_lower=[d.tpr_gain_lower for d in positive if d.tpr_gain_lower is not None],
        seconds=seconds,
        profile=profile,
        decisions=decisions,
    )
