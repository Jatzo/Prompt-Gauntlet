"""Known-answer tests for the Judge's statistics.

Hand cases come from tests/fixtures/known_answer.json (hash-pinned). Simulated cases draw from
distributions whose true values are known in closed form, and check that the intervals cover them.
"""

import json
import math
from pathlib import Path

import numpy as np
import pytest
from pydantic import TypeAdapter

from arena.judge import stats
from arena.judge.stats import ClusteredOutcome, LabelNoise, ScoredItem
from arena.schemas import CategoryKey

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "known_answer.json").read_text())


def phi(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def benign_items(scores, tiebreaks, prefix="b"):
    return [
        ScoredItem(
            score=float(s), is_attack=False, valid=True, cluster=f"{prefix}{i}", tiebreak=float(t)
        )
        for i, (s, t) in enumerate(zip(scores, tiebreaks, strict=True))
    ]


def attack_items(scores, tiebreaks, prefix="a", **extra):
    return [
        ScoredItem(
            score=float(s),
            is_attack=True,
            valid=True,
            cluster=f"{prefix}{i}",
            tiebreak=float(t),
            **extra,
        )
        for i, (s, t) in enumerate(zip(scores, tiebreaks, strict=True))
    ]


def flagged_count(items, threshold):
    return sum(threshold.flags(item.score, item.tiebreak) for item in items)


@pytest.mark.parametrize(
    "case", FIXTURE["threshold"], ids=lambda c: f"{c['scores']}@{c['target_fpr']}"
)
def test_the_threshold_flags_exactly_the_allowed_share(case):
    if case["scores"] == "all 50":
        items = benign_items([50] * 100, [i / 100 for i in range(100)])
    else:
        items = benign_items(range(100), [case["tiebreak"]] * 100)
    threshold = stats.threshold_at_fpr(items, case["target_fpr"])
    assert threshold.score == case["threshold_score"]
    assert flagged_count(items, threshold) == case["flagged"]


def test_an_empty_or_attack_bearing_calibration_set_is_refused():
    with pytest.raises(ValueError):
        stats.threshold_at_fpr([], 0.01)
    with pytest.raises(ValueError):
        stats.threshold_at_fpr(attack_items([1], [0.5]), 0.01)


def test_unscorable_benign_items_use_the_fpr_budget_first():
    scorable = benign_items(range(95), [0.5] * 95)
    unscorable = [
        ScoredItem(
            score=0, is_attack=False, valid=True, cluster=f"u{i}", tiebreak=0.5, scorable=False
        )
        for i in range(5)
    ]
    threshold = stats.threshold_at_fpr(scorable + unscorable, 0.05)
    assert flagged_count(scorable, threshold) == 0


def test_too_many_unscorable_benign_items_make_the_target_unreachable():
    items = benign_items(range(94), [0.5] * 94) + [
        ScoredItem(
            score=0, is_attack=False, valid=True, cluster=f"u{i}", tiebreak=0.5, scorable=False
        )
        for i in range(6)
    ]
    with pytest.raises(stats.TargetUnreachable):
        stats.threshold_at_fpr(items, 0.05)


@pytest.mark.parametrize("case", FIXTURE["auc"], ids=lambda c: str(c["auc"]))
def test_auc_matches_hand_counted_pairs(case):
    assert stats.auc(case["attacks"], case["benign"]) == pytest.approx(case["auc"])


@pytest.mark.parametrize("case", FIXTURE["beta_quantile"], ids=lambda c: f"beta({c['a']},{c['b']})")
def test_beta_quantiles_match_closed_forms(case):
    assert stats.beta_quantile(case["p"], case["a"], case["b"]) == pytest.approx(
        case["x"], abs=1e-9
    )


def test_the_jeffreys_interval_is_symmetric_and_pinned_at_the_edges():
    middle = stats.beta_interval(5, 10, 0.95)
    assert middle.ci_low + middle.ci_high == pytest.approx(1.0, abs=1e-9)
    none = stats.beta_interval(0, 10, 0.95)
    assert none.ci_low == 0.0 and 0 < none.ci_high < 0.3
    all_ = stats.beta_interval(10, 10, 0.95)
    assert all_.ci_high == 1.0


def test_the_fixture_true_tpr_is_the_closed_form_value():
    case = FIXTURE["normal_tpr"]
    assert phi(case["z_99"]) == pytest.approx(0.99, abs=1e-12)
    assert 1 - phi(case["z_99"] - case["attack_mean"]) == pytest.approx(case["true_tpr"], abs=1e-12)


def normal_sets(seed, n_benign=1000, n_attack=400, mean=2.0):
    rng = np.random.default_rng(seed)
    calibration = benign_items(rng.normal(0, 1, n_benign), rng.random(n_benign), prefix="c")
    evaluation = attack_items(rng.normal(mean, 1, n_attack), rng.random(n_attack)) + benign_items(
        rng.normal(0, 1, n_benign), rng.random(n_benign), prefix="e"
    )
    return calibration, evaluation


def test_tpr_intervals_cover_the_true_value():
    truth = FIXTURE["normal_tpr"]["true_tpr"]
    covered = 0
    simulations = 40
    for seed in range(simulations):
        calibration, evaluation = normal_sets(seed)
        result = stats.calibrated_detection(
            calibration,
            evaluation,
            target_fpr=0.01,
            score_kind="verbalised",
            replicates=300,
            confidence=0.95,
            seed=seed,
        )
        covered += result.tpr.ci_low <= truth <= result.tpr.ci_high
    assert covered / simulations >= 0.85


def test_the_achieved_fpr_is_reported_near_the_target():
    calibration, evaluation = normal_sets(7, n_benign=3000)
    result = stats.calibrated_detection(
        calibration,
        evaluation,
        target_fpr=0.01,
        score_kind="verbalised",
        replicates=50,
        confidence=0.95,
        seed=7,
    )
    assert 0.0 < result.achieved_fpr < 0.03
    assert result.n_benign == 3000 and result.n_valid_attacks == 400


def test_auc_is_reported_only_for_logit_scores():
    calibration, evaluation = normal_sets(3)
    kwargs = dict(target_fpr=0.01, replicates=50, confidence=0.95, seed=3)
    assert (
        stats.calibrated_detection(calibration, evaluation, score_kind="verbalised", **kwargs).auc
        is None
    )
    logit = stats.calibrated_detection(calibration, evaluation, score_kind="logit", **kwargs).auc
    true_auc = phi(2.0 / math.sqrt(2))
    assert logit.ci_low <= true_auc <= logit.ci_high


def test_invalid_attacks_are_excluded_from_tpr_and_counted():
    calibration = benign_items(range(100), [0.5] * 100)
    caught = attack_items([200] * 10, [0.5] * 10)
    invalid = [
        ScoredItem(score=-5, is_attack=True, valid=False, cluster=f"x{i}", tiebreak=0.5)
        for i in range(10)
    ]
    result = stats.calibrated_detection(
        calibration,
        caught + invalid,
        target_fpr=0.05,
        score_kind="verbalised",
        replicates=20,
        confidence=0.95,
        seed=1,
    )
    assert result.tpr.value == 1.0
    assert result.n_invalid_attacks == 10


def test_an_unscorable_attack_counts_as_a_miss_and_an_unscorable_benign_item_as_a_false_alarm():
    calibration = benign_items(range(100), [0.5] * 100)
    evaluation = attack_items([200] * 9, [0.5] * 9) + [
        ScoredItem(
            score=200, is_attack=True, valid=True, cluster="ua", tiebreak=0.5, scorable=False
        ),
        ScoredItem(
            score=-5, is_attack=False, valid=True, cluster="ub", tiebreak=0.5, scorable=False
        ),
    ]
    result = stats.calibrated_detection(
        calibration,
        evaluation,
        target_fpr=0.05,
        score_kind="verbalised",
        replicates=20,
        confidence=0.95,
        seed=1,
    )
    assert result.tpr.value == pytest.approx(0.9)
    assert result.achieved_fpr == 1.0
    assert result.n_unscorable == 2


def test_breakdowns_share_the_headline_draws_and_count_their_own_clusters():
    calibration = benign_items(range(200), [0.5] * 200)
    evaluation = attack_items(
        [300] * 30, [0.5] * 30, technique="obfuscation", fold=1
    ) + attack_items([-5] * 30, [0.5] * 30, prefix="m", technique="delimiter", fold=2)
    result = stats.calibrated_detection(
        calibration,
        evaluation,
        target_fpr=0.05,
        score_kind="verbalised",
        replicates=100,
        confidence=0.95,
        seed=2,
    )
    assert result.by_technique["obfuscation"].value == 1.0
    assert result.by_technique["delimiter"].value == 0.0
    assert result.by_fold["fold_one"].clusters == 30
    # The report's breakdown keys must be valid CategoryKeys, or DetectionRow rejects them.
    for key in [*result.by_fold, *result.by_technique]:
        TypeAdapter(CategoryKey).validate_python(key)
    assert result.tpr.value == pytest.approx(0.5)


def test_label_error_widens_the_interval_and_never_moves_the_point():
    calibration, evaluation = normal_sets(11)
    kwargs = dict(
        target_fpr=0.01, score_kind="verbalised", replicates=300, confidence=0.95, seed=11
    )
    plain = stats.calibrated_detection(calibration, evaluation, **kwargs)
    noisy = stats.calibrated_detection(
        calibration, evaluation, noise=LabelNoise(errors=10, audited=100), **kwargs
    )
    assert noisy.tpr.value == plain.tpr.value
    assert noisy.tpr.ci_low <= plain.tpr.ci_low and noisy.tpr.ci_high >= plain.tpr.ci_high
    assert noisy.tpr.ci_high - noisy.tpr.ci_low > plain.tpr.ci_high - plain.tpr.ci_low
    assert noisy.tpr.ci_low <= noisy.tpr.value <= noisy.tpr.ci_high


def test_a_near_zero_label_error_leaves_the_interval_almost_unchanged():
    calibration, evaluation = normal_sets(12)
    kwargs = dict(
        target_fpr=0.01, score_kind="verbalised", replicates=300, confidence=0.95, seed=12
    )
    plain = stats.calibrated_detection(calibration, evaluation, **kwargs)
    clean_audit = stats.calibrated_detection(
        calibration, evaluation, noise=LabelNoise(errors=0, audited=100_000), **kwargs
    )
    assert clean_audit.tpr.ci_low == pytest.approx(plain.tpr.ci_low, abs=0.01)
    assert clean_audit.tpr.ci_high == pytest.approx(plain.tpr.ci_high, abs=0.01)


def test_rate_intervals_cover_a_known_success_probability():
    covered = 0
    simulations = 40
    for seed in range(simulations):
        rng = np.random.default_rng(seed)
        outcomes = [
            ClusteredOutcome(success=bool(rng.random() < 0.4), cluster=f"c{i // 5}")
            for i in range(300)
        ]
        rate = stats.clustered_rate(outcomes, replicates=300, confidence=0.95, seed=seed)
        covered += rate.ci_low <= 0.4 <= rate.ci_high
        assert rate.clusters == 60
    assert covered / simulations >= 0.85


def test_trials_that_move_together_show_a_high_icc():
    together = [
        ClusteredOutcome(success=c % 2 == 0, cluster=f"c{c}") for c in range(20) for _ in range(5)
    ]
    assert stats.icc(together) > 0.95
    rng = np.random.default_rng(5)
    independent = [
        ClusteredOutcome(success=bool(rng.random() < 0.5), cluster=f"c{c}")
        for c in range(200)
        for _ in range(5)
    ]
    assert stats.icc(independent) < 0.1


def scored(scores, attack, cluster_prefix, valid=True):
    return [
        ScoredItem(
            score=float(s),
            is_attack=attack,
            valid=valid,
            cluster=f"{cluster_prefix}{n}",
            tiebreak=0.5,
        )
        for n, s in enumerate(scores)
    ]


def test_a_config_against_itself_shows_no_gain():
    calibration = scored(range(200), False, "b")
    evaluation = scored([150] * 30 + [10] * 30, True, "a")
    same = (calibration, evaluation)
    result = stats.paired_tpr_difference(
        same, same, target_fpr=0.05, replicates=300, confidence=0.95, seed=1
    )
    assert result.difference == 0.0 and result.lower == 0.0
    assert result.clusters == 60


def test_a_candidate_that_catches_every_attack_clears_the_bound():
    calibration = scored(range(200), False, "b")
    misses = scored([10] * 60, True, "a")
    catches = scored([500] * 60, True, "a")
    result = stats.paired_tpr_difference(
        (calibration, misses),
        (calibration, catches),
        target_fpr=0.05,
        replicates=300,
        confidence=0.95,
        seed=1,
    )
    assert result.difference == pytest.approx(1.0) and result.lower == pytest.approx(1.0)


def test_a_small_gain_on_few_clusters_has_a_lower_bound_below_zero_or_near_it():
    calibration = scored(range(200), False, "b")
    before = scored([10] * 20, True, "a")
    after = scored([500] + [10] * 19, True, "a")
    result = stats.paired_tpr_difference(
        (calibration, before),
        (calibration, after),
        target_fpr=0.05,
        replicates=500,
        confidence=0.95,
        seed=3,
    )
    assert result.difference == pytest.approx(0.05)
    assert result.lower <= 0.0


def test_configs_scored_on_different_items_are_refused():
    calibration = scored(range(50), False, "b")
    with pytest.raises(ValueError, match="same items"):
        stats.paired_tpr_difference(
            (calibration, scored([1] * 5, True, "a")),
            (calibration, scored([1] * 5, True, "z")),
            target_fpr=0.05,
            replicates=10,
            confidence=0.95,
            seed=1,
        )


def test_replicates_where_the_candidate_cannot_be_calibrated_count_against_it():
    # 9 unscorable benign items against a budget of 10 at 5% of 200: the full sample calibrates,
    # but many resamples draw more than 10 unscorable items and cannot.
    incumbent_cal = scored(range(200), False, "b")
    fragile_cal = [
        item
        if n >= 9
        else ScoredItem(
            score=0.0,
            is_attack=False,
            valid=True,
            cluster=item.cluster,
            tiebreak=0.5,
            scorable=False,
        )
        for n, item in enumerate(incumbent_cal)
    ]
    result = stats.paired_tpr_difference(
        (incumbent_cal, scored([10] * 60, True, "a")),
        (fragile_cal, scored([500] * 60, True, "a")),
        target_fpr=0.05,
        replicates=400,
        confidence=0.95,
        seed=5,
    )
    assert result.difference == pytest.approx(1.0)
    assert result.lower == -1.0


def test_a_candidate_that_fixes_a_fragile_incumbent_can_still_clear_the_bound():
    robust_cal = scored(range(200), False, "b")
    fragile_cal = [
        item
        if n >= 9
        else ScoredItem(
            score=0.0,
            is_attack=False,
            valid=True,
            cluster=item.cluster,
            tiebreak=0.5,
            scorable=False,
        )
        for n, item in enumerate(robust_cal)
    ]
    result = stats.paired_tpr_difference(
        (fragile_cal, scored([10] * 60, True, "a")),
        (robust_cal, scored([500] * 60, True, "a")),
        target_fpr=0.05,
        replicates=400,
        confidence=0.95,
        seed=5,
    )
    assert result.difference == pytest.approx(1.0)
    assert result.lower == pytest.approx(1.0)
