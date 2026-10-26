import pydantic
import pytest

from arena.config import DEFAULTS, OPEN_WEIGHTS_ROLES, ArenaConfig, config_hash

# Every tunable PLAN.md section 6 names for the defaults table.
SECTION_6_TUNABLES = [
    "max_patch_ops",
    "min_effect_size_tpr",
    "plateau_switch_n",
    "plateau_pause_m",
    "dev_refresh_every_k",
    "cycles_per_run",
    "query_budget_t2",
    "query_budget_t3",
    "review_backlog_cap",
    # thresholds in the keep rule
    "asr_regression_tolerance",
    "max_utility_loss",
    "keep_bootstrap_confidence",
    "per_category_fpr_cap",
    "fold2_replication_min",
    "fresh_evasion_catch_min",
    "target_fpr",
]


@pytest.mark.parametrize("name", SECTION_6_TUNABLES)
def test_every_tunable_named_in_the_plan_is_in_the_defaults_table(name):
    assert hasattr(DEFAULTS, name)


def test_the_hard_usage_cap_is_off_by_default():
    assert DEFAULTS.hard_cap_tokens is None


def test_the_plan_fixed_values_hold():
    assert DEFAULTS.cycles_per_run == 40
    assert DEFAULTS.checkpoint_every == 10
    assert DEFAULTS.lesson_cap == 20
    assert DEFAULTS.max_test_looks == 3
    assert DEFAULTS.schema_failure_window == 50
    assert DEFAULTS.schema_failure_pause_rate == 0.20
    assert DEFAULTS.trials_per_pair >= 5
    assert DEFAULTS.target_temperature > 0


def test_fold_two_replication_needs_half_the_minimum_effect():
    assert DEFAULTS.fold2_replication_min == DEFAULTS.min_effect_size_tpr / 2


def test_the_defaults_cannot_be_changed_at_run_time():
    with pytest.raises(pydantic.ValidationError):
        DEFAULTS.max_patch_ops = 50


def test_an_unknown_setting_is_rejected():
    with pytest.raises(pydantic.ValidationError):
        ArenaConfig(max_patch_opps=5)


def test_every_role_has_a_pinned_model_id():
    for role, model_id in DEFAULTS.models.model_dump().items():
        if role in OPEN_WEIGHTS_ROLES:
            assert model_id and not model_id.startswith("claude-"), role
        else:
            assert model_id.startswith("claude-"), role


def test_the_config_hash_is_stable_and_changes_with_any_value():
    assert config_hash() == config_hash(ArenaConfig())
    assert config_hash() != config_hash(ArenaConfig(max_patch_ops=6))


def test_the_detector_and_weak_target_run_on_haiku_5_5():
    assert DEFAULTS.models.detector == "claude-haiku-5-5"
    assert DEFAULTS.models.target_weak == "claude-haiku-5-5"
