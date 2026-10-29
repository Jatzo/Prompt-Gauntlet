"""A larger synthetic Judge folder, for mock runs of the control arm and the sim battle.

The test folder puts two attack families in dev, one a fold, so no technique sits on both folds and
a change aimed at one technique cannot replicate on fold two (keep condition e). This folder adds
two frames a technique (`templates.EXTRA_ATTACK_FRAMES`) and fills each frame with 40 subjects.

Which technique lands on which fold follows the split's seeded order, so the build seed is chosen,
not left to luck: with it, indirect.email, obfuscation.spacing and override.direct each sit on both
dev folds. A frame edit that changes that fails `tests/test_large_synthetic.py`. It is never a valid
benchmark: the frames are templates.
"""

from pathlib import Path

from arena.config import DEFAULTS, ArenaConfig
from arena.data import templates
from arena.data.build import BuildSummary, build_dataset
from arena.judge.data import TEST_FILES

SUBJECTS_PER_FRAME = 40
# Chosen from five probed seeds: the only one of them that puts three techniques on both folds.
SEED = DEFAULTS.seed + 1
# In families of 40: test 4 (the 2 held out and 2 more), dev 8, train, ablation_eval and monitor
# 2 each; benign: calibration, dev and test 2 each, monitor and ablation_eval 1 each.
SIZES = ArenaConfig(
    seed=SEED,
    dev_min_attacks=8 * SUBJECTS_PER_FRAME,
    dev_min_benign=2 * SUBJECTS_PER_FRAME,
    min_per_benign_category=SUBJECTS_PER_FRAME // 5,
    calibration_min_benign=2 * SUBJECTS_PER_FRAME,
    test_min_attacks=4 * SUBJECTS_PER_FRAME,
    test_min_benign=2 * SUBJECTS_PER_FRAME,
    monitor_attacks=2 * SUBJECTS_PER_FRAME,
    monitor_benign=SUBJECTS_PER_FRAME,
    ablation_eval_attacks=2 * SUBJECTS_PER_FRAME,
    ablation_eval_benign=SUBJECTS_PER_FRAME,
    train_min_attacks=2 * SUBJECTS_PER_FRAME,
    benign_quota_margin=0.0,
    attack_group_train_only_above=60,
)


def corpus() -> list:
    return templates.synthetic_corpus(
        subjects_per_frame=SUBJECTS_PER_FRAME,
        subjects=templates.SUBJECTS + templates.PLACEBO_SUBJECTS,
        extra_frames=True,
    )


def build(judge_dir: Path, private_dir: Path) -> BuildSummary:
    """Its test files are removed, as in the test folder: a mock run never reads test."""
    summary = build_dataset(corpus(), judge_dir=judge_dir, private_dir=private_dir, config=SIZES)
    for name in TEST_FILES:
        (judge_dir / name).unlink(missing_ok=True)
    return summary
