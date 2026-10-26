import json

import pytest

from arena.config import ArenaConfig
from arena.data.build import build_dataset
from arena.data.dedup import deduplicate
from arena.data.feasibility import check_feasible
from arena.data.pairs import build_pairs
from arena.data.splits import split
from arena.data.templates import synthetic_corpus
from arena.judge import data as judge_data
from arena.schemas import Sample
from arena.target.suites import TASKS_BY_ID

# Small minimums, so the synthetic corpus (440 samples) can fill every partition.
SMALL = ArenaConfig(
    dev_min_attacks=40,
    dev_min_benign=40,
    min_per_benign_category=4,
    calibration_min_benign=40,
    test_min_attacks=40,
    test_min_benign=40,
    monitor_attacks=20,
    monitor_benign=20,
    ablation_eval_attacks=20,
    ablation_eval_benign=20,
)


def corpus():
    return synthetic_corpus()


def test_the_synthetic_corpus_has_attacks_and_benign_in_every_channel():
    samples = corpus()
    assert {s.label for s in samples} == {"attack", "benign"}
    assert {s.channel for s in samples} == {"email", "document", "tool_output"}
    assert all("{ATTACKER}" in s.text for s in samples if s.label == "attack")


def test_exact_duplicates_are_removed_and_counted():
    sample = corpus()[0]
    copy = sample.model_copy(update={"id": "copy", "text": sample.text.upper()})
    report = deduplicate([sample, copy])
    assert report.exact_removed == 1 and len(report.kept) == 1


def test_a_near_duplicate_from_another_group_is_removed_but_relatives_stay():
    samples = corpus()
    base = samples[0]
    near = base.model_copy(
        update={
            "id": "near",
            "text": base.text + " ok",
            "template_family": "other",
            "cluster_id": "x",
        }
    )
    report = deduplicate([*samples, near])
    assert report.near_removed == 1
    assert len(report.kept) == len(samples)


def test_groups_never_straddle_partitions():
    rows = split(corpus(), SMALL)
    families: dict[str, set[str]] = {}
    clusters: dict[str, set[str]] = {}
    for row in rows:
        families.setdefault(row.sample.template_family, set()).add(row.sample.partition)
        clusters.setdefault(row.sample.cluster_id, set()).add(row.sample.partition)
    assert all(len(parts) == 1 for parts in families.values())
    assert all(len(parts) == 1 for parts in clusters.values())


def test_calibration_holds_benign_samples_only_and_dev_has_two_folds():
    rows = split(corpus(), SMALL)
    assert all(r.sample.label == "benign" for r in rows if r.sample.partition == "calibration")
    assert {r.fold for r in rows if r.sample.partition == "dev"} == {1, 2}
    assert all(r.fold is None for r in rows if r.sample.partition != "dev")


def test_held_out_techniques_and_generators_go_to_test_only():
    samples = corpus()
    odd = samples[0].model_copy(update={"id": "odd", "generator_family": "other_family"})
    config = SMALL.model_copy(
        update={
            "held_out_techniques": ("exfiltration.markdown",),
            "test_only_generator_families": ("other_family",),
        }
    )
    rows = split([*samples, odd], config)
    for row in rows:
        if row.sample.technique == "exfiltration.markdown" or row.sample.id == "odd":
            assert row.sample.partition == "test"


def test_the_split_is_the_same_every_time_for_the_same_seed():
    first = [(r.sample.id, r.sample.partition, r.fold) for r in split(corpus(), SMALL)]
    again = [(r.sample.id, r.sample.partition, r.fold) for r in split(corpus(), SMALL)]
    assert first == again


def test_pairs_inherit_partition_and_cluster_and_match_the_task_channel():
    rows = split(corpus(), SMALL)
    samples = {r.sample.id: r.sample for r in rows}
    pairs = build_pairs(list(samples.values()))
    assert pairs
    for pair in pairs:
        sample = samples[pair.payload_sample_id]
        assert pair.partition == sample.partition != "train"
        assert pair.cluster_id == sample.cluster_id
        assert TASKS_BY_ID[pair.task_id].reads == sample.channel


def test_feasibility_names_every_shortfall():
    rows = split(corpus(), SMALL)
    assert check_feasible(rows, SMALL).ok
    report = check_feasible(rows, ArenaConfig())
    assert not report.ok
    assert any("dev has" in line and "needs 1000" in line for line in report.shortfalls)


# The written dataset and the Judge's custody of it


@pytest.fixture
def built(tmp_path):
    judge_dir, private_dir = tmp_path / "judge", tmp_path / "private"
    summary = build_dataset(corpus(), judge_dir=judge_dir, private_dir=private_dir, config=SMALL)
    return summary, judge_dir, private_dir


def test_the_build_writes_every_partition_where_it_belongs(built):
    summary, judge_dir, private_dir = built
    assert summary.feasibility.ok
    for name in judge_data.MEASURABLE:
        assert (judge_dir / "partitions" / f"{name}.jsonl").exists()
    assert (judge_dir / "test.jsonl").exists() and (judge_dir / "test_pairs.jsonl").exists()
    assert (private_dir / "train.jsonl").exists()
    assert not (judge_dir / "partitions" / "train.jsonl").exists()


def test_the_judge_opens_measurable_partitions_and_refuses_test(built):
    _, judge_dir, _ = built
    opened = judge_data.open_partitions(judge_dir, ("calibration", "dev"))
    assert opened["dev"].rows and opened["dev"].pairs
    with pytest.raises(PermissionError):
        judge_data.open_partitions(judge_dir, ("test",))
    with pytest.raises(PermissionError):
        judge_data.open_partitions(judge_dir, ("train",))


# The tamper matrix


@pytest.fixture
def sealed(built, tmp_path):
    summary, judge_dir, _ = built
    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    (root / "data" / "test.sha256").write_text(summary.test_pin)
    assert judge_data.verify_test_set(root, judge_dir) == "ok"
    return root, judge_dir


def rewrite(path, change):
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(change(lines)))


def flip_byte(lines):
    first = lines[0]
    return [first.replace("a", "b", 1), *lines[1:]]


@pytest.mark.parametrize(
    ("tamper", "status"),
    [
        (lambda lines: flip_byte(lines), "mismatch"),
        (lambda lines: [*lines, lines[0]], "size_mismatch"),
        (lambda lines: lines[1:], "size_mismatch"),
        (lambda lines: list(reversed(lines)), "mismatch"),
        (lambda lines: [lines[0][:-5] + "\n"], "size_mismatch"),
        (lambda lines: [], "size_mismatch"),
    ],
    ids=["byte-flip", "row-added", "row-removed", "reordered", "truncated", "emptied"],
)
def test_every_kind_of_tampering_with_the_test_set_is_caught(sealed, tamper, status):
    root, judge_dir = sealed
    rewrite(judge_dir / "test.jsonl", tamper)
    assert judge_data.verify_test_set(root, judge_dir) == status


def test_an_edited_pin_without_the_file_is_caught(sealed):
    root, judge_dir = sealed
    pin = root / "data" / "test.sha256"
    pin.write_text(
        pin.read_text().replace(pin.read_text()[0], "0" if pin.read_text()[0] != "0" else "1", 1)
    )
    assert judge_data.verify_test_set(root, judge_dir) == "mismatch"


def test_a_wrong_size_in_the_pin_is_caught(sealed):
    root, judge_dir = sealed
    pin = root / "data" / "test.sha256"
    lines = pin.read_text().splitlines()
    digest, size, name = lines[0].split()
    lines[0] = f"{digest}  {int(size) + 1}  {name}"
    pin.write_text("\n".join(lines) + "\n")
    assert judge_data.verify_test_set(root, judge_dir) == "size_mismatch"


def test_a_placeholder_pin_beside_real_test_files_is_a_mismatch(sealed):
    root, judge_dir = sealed
    (root / "data" / "test.sha256").write_text("PLACEHOLDER: not sealed\n")
    assert judge_data.verify_test_set(root, judge_dir) == "mismatch"


def test_a_missing_test_file_is_reported(sealed):
    root, judge_dir = sealed
    (judge_dir / "test_pairs.jsonl").unlink()
    assert judge_data.verify_test_set(root, judge_dir) == "missing_test_set"


def test_a_crlf_checkout_of_the_test_set_still_verifies(sealed):
    root, judge_dir = sealed
    path = judge_dir / "test.jsonl"
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert judge_data.verify_test_set(root, judge_dir) == "ok"


def test_partition_rows_round_trip_as_samples(built):
    _, judge_dir, _ = built
    line = (judge_dir / "partitions" / "dev.jsonl").read_text().splitlines()[0]
    row = json.loads(line)
    assert Sample.model_validate(row["sample"]).partition == "dev"
    assert row["fold"] in (1, 2)


def test_every_build_clears_any_old_label_error_and_the_fingerprint_sees_it(tmp_path):
    from arena.judge import measure

    judge_dir = tmp_path / "judge"
    build = dict(judge_dir=judge_dir, private_dir=tmp_path / "private", config=SMALL)
    build_dataset(corpus(), **build)
    clean = measure._fingerprint(judge_dir, measure.DATA_FILES)
    # A label-error rate left from an older, audited build must not survive a rebuild.
    (judge_dir / "labels.json").write_text(json.dumps({"dev": {"errors": 3, "audited": 50}}))
    assert judge_data.label_noise(judge_dir)
    assert measure._fingerprint(judge_dir, measure.DATA_FILES) != clean

    build_dataset(corpus(), **build)
    assert judge_data.label_noise(judge_dir) == {}
    assert json.loads((judge_dir / "contested.json").read_text()) == {}
    assert measure._fingerprint(judge_dir, measure.DATA_FILES) == clean


def test_a_rebuild_cannot_replace_a_sealed_test_set(sealed, tmp_path):
    from arena.data.build import SealedTestSet

    root, judge_dir = sealed
    before = (judge_dir / "test.jsonl").read_bytes()
    rebuild = dict(judge_dir=judge_dir, private_dir=tmp_path / "private", root=root)

    changed = [s.model_copy(update={"text": s.text + " Thanks."}) for s in corpus()]
    with pytest.raises(SealedTestSet):
        build_dataset(changed, config=SMALL, **rebuild)
    assert (judge_dir / "test.jsonl").read_bytes() == before

    # The same corpus and config write the same bytes, which the seal allows.
    build_dataset(corpus(), config=SMALL, **rebuild)
    assert judge_data.verify_test_set(root, judge_dir) == "ok"
