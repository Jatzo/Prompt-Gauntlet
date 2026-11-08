"""The keep rule when dev holds no valid attack on the reference target, the arena's state on guided
Gemma (PLAN section 7 note of 2026-11-08). The candidate must be rejected cleanly, and the report
must survive the Judge process's JSON reply and the client's validation."""

import json

import pytest

from arena import baselines
from arena.config import DEFAULTS, REPO_ROOT
from arena.data.build import build_dataset
from arena.data.templates import synthetic_corpus
from arena.judge import keep, measure, store
from arena.schemas import EvaluateRequest, JudgeReport
from arena.target.ladder import LADDER
from tests.test_baseline import SMALL
from tests.test_keep import ADDRESS_RULE, REGEX


@pytest.fixture
def no_valid_report(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_LLM_BACKEND", "mock")
    monkeypatch.setattr(measure, "validity", lambda measurement, reference: set())
    judge_dir = tmp_path / "judge"
    build_dataset(synthetic_corpus(), judge_dir=judge_dir, private_dir=tmp_path / "p", config=SMALL)
    conn = store.connect(tmp_path / "judge.db")
    context = measure.Context(REPO_ROOT, judge_dir, store.EvalCache(conn))
    settings = baselines.request(
        backend="mock",
        targets=[LADDER[1]],
        reference=LADDER[1],
        trials=2,
        seed=DEFAULTS.seed,
        replicates=200,
    ).model_copy(update={"arms": [REGEX]})
    request = EvaluateRequest(cycle_id=1, candidate=ADDRESS_RULE, primary_fold=1, measure=settings)
    yield keep.evaluate(request, context, conn)
    conn.close()


def test_no_valid_attack_rejects_with_no_tpr_gain(no_valid_report):
    assert (no_valid_report.decision, no_valid_report.reason_code) == ("reject", "no_tpr_gain")


def test_the_report_survives_the_judge_reply(no_valid_report):
    # The same path as arena/judge/process.py: model_dump(mode="json"), then json.dumps per line.
    wire = json.dumps(no_valid_report.model_dump(mode="json"))
    back = JudgeReport.model_validate(json.loads(wire))
    assert back.decision == "reject"


def test_the_gain_really_had_no_denominator(no_valid_report):
    gain = no_valid_report.conditions["tpr_gain"]
    assert gain.passed is False
    assert gain.value is None or gain.value != gain.value  # None after JSON, or NaN in process
