"""The large synthetic folder: the extra frames, its sizes and its dev fold layout."""

import hashlib
import json
from collections import defaultdict

import pytest

from arena import cli, taxonomy
from arena.data import large_synthetic, templates
from arena.judge.data import TEST_FILES
from arena.target.world import ATTACKER_ADDRESS

# The default corpus, as every other test builds it. The extra frames are opt-in, so this stays.
# Update it only for a deliberate change to the default frames, and say why in PROGRESS.md.
DEFAULT_CORPUS_SHA = "fdbb64a6653327c11b69b99f9ab073827f01871988dd18f3ea6884f827389bb4"
CHANNELS = {technique: channel for technique, _, channel, _ in templates.ATTACK_FAMILIES}


def test_the_default_corpus_is_unchanged_by_the_extra_frames():
    rows = sorted(
        (s.id, s.text, s.label, s.technique, s.template_family)
        for s in templates.synthetic_corpus()
    )
    assert hashlib.sha256(json.dumps(rows).encode()).hexdigest() == DEFAULT_CORPUS_SHA


def test_each_technique_not_held_out_gets_two_extra_frames():
    attack_techniques = set(CHANNELS) - set(large_synthetic.SIZES.held_out_techniques)
    assert set(templates.EXTRA_ATTACK_FRAMES) == attack_techniques
    assert all(len(frames) == 2 for frames in templates.EXTRA_ATTACK_FRAMES.values())


def test_the_large_plan_counts_match_the_large_build(built):
    from arena.data.build import plan_dataset

    summary, _ = built
    _, _, feasibility = plan_dataset(large_synthetic.corpus(), large_synthetic.SIZES)
    assert feasibility.counts == summary.counts


def test_pilot_is_refused_without_real(tmp_path):
    with pytest.raises(SystemExit) as refused:
        cli.main(["data", "build", "--synthetic", "--pilot", "5", "--judge-dir", str(tmp_path)])
    assert refused.value.code == 2


def test_every_extra_frame_is_classified_as_its_own_technique():
    for technique, frames in templates.EXTRA_ATTACK_FRAMES.items():
        assert technique in CHANNELS and technique not in large_synthetic.SIZES.held_out_techniques
        for frame in frames:
            text = frame.replace("{subject}", "budget").replace("{ATTACKER}", ATTACKER_ADDRESS)
            assert taxonomy.classify(text, CHANNELS[technique]) == technique, frame


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("large")
    summary = large_synthetic.build(root / "judge", root / "private")
    return summary, root / "judge"


def test_every_partition_meets_its_minimum_and_no_test_file_is_left(built):
    summary, judge_dir = built
    assert summary.feasibility.ok, summary.feasibility.shortfalls
    for name in TEST_FILES:
        assert not (judge_dir / name).exists()


def test_three_techniques_sit_on_both_dev_folds_and_no_family_was_merged(built):
    _, judge_dir = built
    folds = defaultdict(set)
    for line in (judge_dir / "partitions" / "dev.jsonl").read_text().splitlines():
        row = json.loads(line)
        if row["sample"]["label"] == "attack":
            folds[row["fold"]].add((row["sample"]["technique"], row["sample"]["template_family"]))
    # Eight families of 40, four a fold: a merge by the containment rule would change the count.
    assert [len(folds[1]), len(folds[2])] == [4, 4]
    both = {t for t, _ in folds[1]} & {t for t, _ in folds[2]}
    assert both == {"indirect.email", "obfuscation.spacing", "override.direct"}


def test_large_is_refused_without_synthetic(tmp_path):
    with pytest.raises(SystemExit) as refused:
        cli.main(["data", "build", "--real", "--large", "--judge-dir", str(tmp_path)])
    assert refused.value.code == 2
