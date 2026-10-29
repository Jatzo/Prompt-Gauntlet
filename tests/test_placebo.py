"""The placebo test (Phase 3 step 8): inert variants, the bound, counting and a real Judge run."""

import json

import pytest
from test_baseline import SMALL

from arena import baselines, cli
from arena.control import placebo
from arena.detector.normalisers import normalise
from arena.judge.data import TEST_FILES
from arena.orchestrator import REFERENCE_TARGET
from arena.schemas import BatchReport, Condition, JudgeReport

PASS = Condition(passed=True, value=0.1, limit=0.02)
SKIP = Condition(passed=None, value=0.0, limit=0.5)


@pytest.fixture(scope="module")
def folder(tmp_path_factory):
    root = tmp_path_factory.mktemp("placebo")
    placebo.build_folder(root / "judge", root / "build")
    return root / "judge"


def every_text(judge_dir) -> list[str]:
    """Every text a placebo cycle could score: each partition, each pair and the fixed batch."""
    texts = [attack.text for attack in placebo.fixed_batch()]
    for path in judge_dir.rglob("*.jsonl"):
        texts += path.read_text().splitlines()
    return texts


def test_the_placebo_folder_meets_its_sizes_and_holds_no_test_files(folder):
    for name in TEST_FILES:
        assert not (folder / name).exists()
    dev = (folder / "partitions" / "dev.jsonl").read_text().splitlines()
    calibration = (folder / "partitions" / "calibration.jsonl").read_text().splitlines()
    attacks = [row for row in dev if '"label": "attack"' in row or '"label":"attack"' in row]
    assert len(attacks) >= placebo.FOLDER_SIZES.dev_min_attacks
    assert len(calibration) >= placebo.FOLDER_SIZES.calibration_min_benign


def test_placebo_variants_differ_from_each_other_and_from_the_incumbent():
    prompts = {placebo.placebo_variant(index).classifier_prompt for index in range(1, 301)}
    assert len(prompts) == 300
    assert baselines.ZERO_SHOT.classifier_prompt not in prompts


def test_the_reserved_marker_occurs_in_no_text_a_placebo_scores(folder):
    lowered = placebo.RESERVED_MARKER.lower()
    assert not any(lowered in text.lower() for text in every_text(folder))


def test_the_swapped_normalisers_give_the_same_text_for_everything_scored(folder):
    original = list(baselines.ZERO_SHOT.normalisers)
    swapped = list(placebo.normaliser_swap_variant().normalisers)
    assert swapped != original
    for text in every_text(folder):
        assert normalise(text, swapped) == normalise(text, original)


def test_sixty_cycles_is_the_fewest_at_which_no_keeps_passes():
    assert placebo.upper_bound(0, 60) < 0.05 <= placebo.upper_bound(0, 58)
    assert placebo.minimum_cycles() == 60
    assert placebo.upper_bound(0, 300) == pytest.approx(1 - 0.05 ** (1 / 300))
    assert placebo.upper_bound(5, 5) == 1.0


class ScriptedJudge:
    """Keeps the cycles it is told to keep, and records what it was asked."""

    def __init__(self, keep_ids=(), held_back=1):
        self.keep_ids = set(keep_ids)
        self.held_back = held_back
        self.requests = []

    def validate_batch(self, request):
        return BatchReport(verdicts=[], evading_clusters=0, held_back_clusters=self.held_back)

    def evaluate_candidate(self, request):
        self.requests.append(request)
        kept = request.cycle_id in self.keep_ids
        conditions = {
            name: PASS
            for name in ("asr", "utility", "tpr_gain", "category_fpr", "regression", "fold_two")
        } | {"fresh_evasions": SKIP}
        return JudgeReport(
            asr=None,
            utility=None,
            tpr_at_target_fpr=None,
            achieved_fpr=None,
            per_category_fpr={},
            regression_status="not_run",
            decision="keep" if kept else "reject",
            reason_code="kept" if kept else "no_tpr_gain",
            conditions=conditions,
        )


BASE = baselines.request(
    backend="mock", targets=[REFERENCE_TARGET], reference=REFERENCE_TARGET, trials=2, seed=7
)


def test_a_run_alternates_folds_moves_the_seed_and_runs_the_checks_last():
    judge = ScriptedJudge()
    result = placebo.run(judge, cycles=4, base=BASE, positive_runs=2)
    kinds = [d.kind for d in result.decisions]
    assert (
        kinds == ["placebo"] * 4 + ["reserved_marker", "normaliser_swap"] + ["positive_control"] * 2
    )
    assert [r.primary_fold for r in judge.requests[:4]] == [1, 2, 1, 2]
    assert [r.measure.seed for r in judge.requests] == [8, 9, 10, 11, 12, 13, 14, 15]
    assert len({r.cycle_id for r in judge.requests}) == 8
    assert all(r.measure.arms[0].detector == baselines.ZERO_SHOT for r in judge.requests)


def test_every_candidate_is_built_on_the_incumbent_it_is_compared_with():
    incumbent = baselines.ZERO_SHOT.model_copy(
        update={
            "rules": baselines.REGEX_RULES.rules,
            "layers": ["normalise", "rules", "classifier"],
        }
    )
    judge = ScriptedJudge()
    placebo.run(judge, cycles=2, base=BASE, incumbent=incumbent, positive_runs=1)
    for request in judge.requests:
        assert request.candidate.rules[: len(incumbent.rules)] == incumbent.rules
        assert request.candidate.classifier_prompt.startswith(incumbent.classifier_prompt)


def test_keeps_the_bound_and_each_verdict_are_counted_from_the_decisions():
    # Cycle 2 is a placebo keep (fold 2), and 2 of the 3 positive controls are kept.
    judge = ScriptedJudge(keep_ids={2, 7, 8})
    result = placebo.run(judge, cycles=4, base=BASE, positive_runs=3)
    assert (result.cycles, result.keeps, result.rate) == (4, 1, 0.25)
    assert result.keeps_by_fold == {1: 0, 2: 1}
    assert result.bound == pytest.approx(placebo.upper_bound(1, 4))
    assert not result.passed
    assert result.determinism_rejected
    assert (result.positive_keeps, result.positive_runs, result.positive_passed) == (2, 3, True)
    assert result.fresh_evasions_applied == 0
    assert result.condition_pass_rate["asr"] == 1.0


def test_a_kept_determinism_check_or_a_rejected_positive_control_fails_its_verdict():
    result = placebo.run(ScriptedJudge(keep_ids={5}), cycles=4, base=BASE, positive_runs=2)
    assert not result.determinism_rejected
    assert not result.positive_passed


def test_a_positive_control_kept_in_exactly_half_its_runs_fails():
    # Placebo cycles 1 and 2, checks 3 and 4, positive controls 5 and 6.
    result = placebo.run(ScriptedJudge(keep_ids={5}), cycles=2, base=BASE, positive_runs=2)
    assert (result.positive_keeps, result.positive_runs) == (1, 2)
    assert not result.positive_passed


def test_an_odd_cycle_count_is_refused():
    with pytest.raises(ValueError, match="even"):
        placebo.run(ScriptedJudge(), cycles=3, base=BASE)


@pytest.mark.parametrize("cycles", ["58", "61"])
def test_the_command_refuses_too_few_or_odd_cycles(cycles):
    with pytest.raises(SystemExit) as refused:
        cli.main(["placebo", "--cycles", cycles])
    assert refused.value.code == 2


def test_the_written_summary_is_aggregates_and_one_decision_per_cycle():
    result = placebo.run(ScriptedJudge(), cycles=2, base=BASE, positive_runs=1)
    saved = json.loads(json.dumps(result.summary()))
    assert len(saved["decisions"]) == 5
    assert set(saved["decisions"][0]) == {
        "cycle_id",
        "kind",
        "primary_fold",
        "decision",
        "reason_code",
        "conditions",
        "tpr_gain_lower",
        "held_back_clusters",
    }


def test_a_short_run_through_the_judge_process_decides_every_cycle(built_judge, monkeypatch):
    from arena.judge_client import JudgeClient

    monkeypatch.setenv("ARENA_LLM_BACKEND", "mock")
    base = BASE.model_copy(update={"profile": "placebo", "replicates": 200})
    with JudgeClient(judge_dir=built_judge) as judge:
        result = placebo.run(judge, cycles=2, base=base, positive_runs=1)
    assert [d.decision for d in result.decisions[2:4]] == ["reject", "reject"]
    assert all(d.decision in ("keep", "reject") for d in result.decisions)
    assert set(result.decisions[0].conditions) == {
        "asr",
        "utility",
        "tpr_gain",
        "category_fpr",
        "regression",
        "fold_two",
        "fresh_evasions",
    }


def test_the_small_test_folder_still_builds_from_the_original_subjects():
    from arena.data.templates import PLACEBO_SUBJECTS, SUBJECTS, synthetic_corpus

    corpus = synthetic_corpus()
    assert len(corpus) == 440
    assert not any(subject in sample.text for sample in corpus for subject in PLACEBO_SUBJECTS[:5])
    assert SMALL.dev_min_attacks < placebo.FOLDER_SIZES.dev_min_attacks
    assert len(SUBJECTS) == 20
