"""The checker pass and the contested-FPR row, both inside the Judge (operator-decisions Part 3)."""

import json

import pytest
from test_baseline import SMALL

from arena import baselines
from arena.config import DEFAULTS, REPO_ROOT
from arena.data.build import build_dataset
from arena.data.templates import synthetic_corpus
from arena.judge import data as judge_data
from arena.judge import labelcheck, measure, store
from arena.schemas import LabelCheckRequest
from arena.target.ladder import LADDER


@pytest.fixture
def built(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_LLM_BACKEND", "mock")
    judge_dir = tmp_path / "judge"
    build_dataset(synthetic_corpus(), judge_dir=judge_dir, private_dir=tmp_path / "p", config=SMALL)
    conn = store.connect(tmp_path / "judge.db")
    yield judge_dir, measure.Context(REPO_ROOT, judge_dir, store.EvalCache(conn))
    conn.close()


def check_request(targets=(LADDER[0],)):
    return LabelCheckRequest(
        measure=baselines.request(
            backend="mock",
            targets=list(targets),
            reference=targets[0],
            trials=2,
            seed=DEFAULTS.seed,
            replicates=50,
        )
    )


def test_every_attack_in_every_partition_is_checked_and_counted(built):
    judge_dir, context = built
    report = labelcheck.run(check_request(), context)
    partitions = judge_data.label_partitions(REPO_ROOT, judge_dir)
    assert set(report.partitions) == set(partitions)
    for name, counts in report.partitions.items():
        attacks = sum(row.sample.label == "attack" for row in partitions[name].rows)
        total = counts.confirmed + counts.rung_only + counts.invalid + counts.unpaired
        assert total == attacks, name
    assert sum(c.confirmed for c in report.partitions.values()) > 0
    record = json.loads((judge_dir / "checker.json").read_text())
    assert record["reference_target"] == LADDER[0].key and record["trials"] == 2
    assert {item["outcome"] for item in record["items"].values()} <= {
        "confirmed",
        "rung_only",
        "invalid",
        "unpaired",
    }


def test_a_confirmed_attack_takes_its_impact_class_from_what_the_app_did(built):
    judge_dir, context = built
    labelcheck.run(check_request(), context)
    record = json.loads((judge_dir / "checker.json").read_text())["items"]
    samples = {
        row.sample.id: row.sample
        for partition in judge_data.label_partitions(REPO_ROOT, judge_dir).values()
        for row in partition.rows
    }
    confirmed = [i for i, item in record.items() if item["outcome"] == "confirmed"]
    assert confirmed
    for sample_id in confirmed:
        expected = labelcheck.impact_of(frozenset(record[sample_id]["signals"]))
        assert samples[sample_id].impact_class == expected


def test_signals_map_to_impact_classes():
    assert labelcheck.impact_of(frozenset({"canary_in_output"})) == "data_theft"
    assert (
        labelcheck.impact_of(frozenset({"sent_to_attacker", "canary_in_tool_arg"})) == "data_theft"
    )
    assert labelcheck.impact_of(frozenset({"sent_to_attacker"})) == "unauthorised_action"


def test_rung_only_confirmations_are_counted_apart(built):
    _, context = built
    report = labelcheck.run(check_request(targets=(LADDER[0], *LADDER[1:])), context)
    one_rung = labelcheck.run(check_request(), context)
    for name, counts in report.partitions.items():
        alone = one_rung.partitions[name]
        assert counts.confirmed == alone.confirmed
        assert counts.rung_only + counts.invalid == alone.rung_only + alone.invalid


def test_the_checker_pass_is_refused_once_the_test_set_is_sealed(built, tmp_path):
    judge_dir, context = built
    root = tmp_path / "repo"
    (root / "data").mkdir(parents=True)
    (root / "data" / "test.sha256").write_text("abc  10  test.jsonl\n")
    sealed = measure.Context(root, judge_dir, context.cache)
    with pytest.raises(PermissionError, match="sealed"):
        labelcheck.run(check_request(), sealed)


def test_the_report_adds_the_contested_fpr_row_and_the_fingerprint_sees_the_file(built):
    judge_dir, context = built
    before = measure._fingerprint(judge_dir, measure.DATA_FILES)
    (judge_dir / "contested.json").write_text(json.dumps({"dev": {"email": 6, "code": 4}}))
    assert measure._fingerprint(judge_dir, measure.DATA_FILES) != before
    report = measure.run(check_request().measure, context)
    rows = [row for row in report.detection if row.fpr_if_contested is not None]
    assert rows
    for row in rows:
        found = row.fpr_if_contested
        flagged = round(row.achieved_fpr * row.benign)
        assert found.contested == 10
        assert found.all_clear == pytest.approx(flagged / (row.benign + 10))
        assert found.all_flagged == pytest.approx((flagged + 10) / (row.benign + 10))
        assert found.all_clear <= row.achieved_fpr <= found.all_flagged


def test_no_contested_items_means_no_sensitivity_row(built):
    _, context = built
    report = measure.run(check_request().measure, context)
    assert all(row.fpr_if_contested is None for row in report.detection)


def test_cli_data_check_runs_the_pass_in_the_judge_process(tmp_path):
    import os
    import subprocess
    import sys

    judge_dir = tmp_path / "judge"
    build_dataset(synthetic_corpus(), judge_dir=judge_dir, private_dir=tmp_path / "p", config=SMALL)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arena.cli",
            "data",
            "check",
            "--backend",
            "mock",
            "--trials",
            "2",
            "--judge-dir",
            str(judge_dir),
        ],
        cwd=REPO_ROOT,
        env=dict(os.environ, ARENA_LLM_BACKEND="mock"),
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, result.stderr
    assert "confirmed" in result.stdout and "test:" in result.stdout
    assert (judge_dir / "checker.json").exists()


def test_only_confirmed_attacks_have_their_impact_class_changed(built):
    judge_dir, context = built
    before = {
        row.sample.id: row.sample.impact_class
        for partition in judge_data.label_partitions(REPO_ROOT, judge_dir).values()
        for row in partition.rows
    }
    labelcheck.run(check_request(), context)
    items = json.loads((judge_dir / "checker.json").read_text())["items"]
    after = {
        row.sample.id: row.sample.impact_class
        for partition in judge_data.label_partitions(REPO_ROOT, judge_dir).values()
        for row in partition.rows
    }
    for sample_id, impact in after.items():
        if items.get(sample_id, {}).get("outcome") != "confirmed":
            assert impact == before[sample_id], sample_id


def test_a_failed_pass_writes_no_partition_file(built, monkeypatch):
    judge_dir, context = built
    files = sorted((judge_dir / "partitions").glob("*.jsonl")) + [judge_dir / "test.jsonl"]
    before = {path: path.read_bytes() for path in files}
    calls = []

    def fail_on_test(played, target):
        calls.append(target)
        if any(s.partition == "test" for s in played.samples.values()):
            raise RuntimeError("target error")
        return real(played, target)

    real = measure.success_signals
    monkeypatch.setattr(measure, "success_signals", fail_on_test)
    with pytest.raises(RuntimeError):
        labelcheck.run(check_request(), context)
    assert calls
    assert {path: path.read_bytes() for path in files} == before
    assert not (judge_dir / "checker.json").exists()


def test_a_placeholder_pin_allows_the_pass():
    assert (
        (REPO_ROOT / "data" / "test.sha256").read_text().startswith(judge_data.PLACEHOLDER_PREFIX)
    )
    assert not judge_data.sealed(REPO_ROOT)


def test_a_rebuild_removes_the_old_checker_record(built, tmp_path):
    judge_dir, context = built
    labelcheck.run(check_request(), context)
    assert (judge_dir / "checker.json").exists()
    build_dataset(synthetic_corpus(), judge_dir=judge_dir, private_dir=tmp_path / "p", config=SMALL)
    assert not (judge_dir / "checker.json").exists()
