"""Rungs 4 and 5, the engineered open-model targets, and what must not move when they are added.

The earlier rungs' prompts and keys are pinned: if either changed, every cached answer for rungs 0
to 3 would miss and those rungs would run again on Claude.
"""

import hashlib
from argparse import Namespace

import pytest
from fakes import MemoryEvalCache
from pydantic import TypeAdapter

from arena import baselines, cli, orchestrator
from arena.config import DEFAULTS, ArenaConfig
from arena.schemas import TargetKey
from arena.simulated import SimulatedBackend
from arena.target import app, ladder
from arena.target.arms import NoDefence, PlanThenExecute
from arena.target.sim import target_policy
from arena.target.suites import benign_cases

EARLIER_KEYS = [
    "target_strong.strict.standard",
    "target_weak.strict.standard",
    "target_weak.permissive.risky",
    "target_open.strict.standard",
]


def test_the_standard_prompts_are_byte_for_byte_unchanged():
    digests = [
        hashlib.sha256(text.encode()).hexdigest()[:12]
        for text in (app.SYSTEM_PROMPT, app.PLAN_PROMPT)
    ]
    assert digests == ["fffcff2da713", "04985c78d110"]


def test_the_keys_of_rungs_0_to_3_are_unchanged():
    assert [spec.key for spec in ladder.LADDER[:4]] == EARLIER_KEYS


def test_rung_4_is_the_open_model_with_permissive_tools_and_risky_placements():
    rung = ladder.LADDER[4]
    assert (rung.model, rung.tools, rung.placements, rung.prompt) == (
        "target_open",
        "permissive",
        "risky",
        "standard",
    )


def test_rung_5_is_rung_4_told_to_oblige_and_its_key_is_valid():
    rung = ladder.LADDER[5]
    assert rung.model_copy(update={"prompt": "standard"}) == ladder.LADDER[4]
    assert rung.key == "target_open.permissive.risky.obliging"
    assert TypeAdapter(TargetKey).validate_python(rung.key) == rung.key


def test_a_request_may_measure_all_six_rungs():
    request = baselines.request(
        backend="mock", targets=list(ladder.LADDER), reference=ladder.LADDER[0], trials=1, seed=1
    )
    assert len(request.targets) == 6


def recording_backend():
    seen = []
    policy = target_policy(obey=0.0, complete=1.0, seed=1)

    def recording(request, rng):
        seen.append((request.tool, request.system))
        return policy(request, rng)

    return SimulatedBackend({"target_open": recording}, seed=1), seen


def play(target, defence):
    backend, seen = recording_backend()
    app.run_episodes(
        benign_cases(DEFAULTS.seed, target.tools),
        target=target,
        defence=defence,
        trials=1,
        cache=MemoryEvalCache(),
        backend=backend,
    )
    return seen


def test_the_obliging_line_reaches_every_act_call_and_never_the_plan_call():
    seen = play(ladder.LADDER[5], PlanThenExecute())
    acts = [system for tool, system in seen if tool == "act"]
    plans = [system for tool, system in seen if tool == "plan"]
    assert acts and plans
    assert all(system.endswith(app.OBLIGING_LINE) for system in acts)
    assert not any(app.OBLIGING_LINE in system for system in plans)


def test_rung_4_act_calls_carry_the_standard_system_prompt_exactly():
    notes = benign_cases(DEFAULTS.seed, "permissive")[0].world.private_notes
    seen = play(ladder.LADDER[4], NoDefence())
    assert {system for _, system in seen} == {app.SYSTEM_PROMPT.format(notes=notes)}


def test_the_data_check_plays_exactly_rungs_0_to_3():
    assert ladder.DATA_CHECK_RUNGS == ladder.LADDER[:4]


def test_the_cycles_and_the_cli_use_the_one_reference_rung():
    assert orchestrator.REFERENCE_TARGET == ladder.reference_target(DEFAULTS) == ladder.LADDER[0]
    assert ladder.reference_target(ArenaConfig(reference_rung=5)) == ladder.LADDER[5]


class CapturingJudge:
    """Records the request it is sent, then stops the command before any measurement."""

    requests = []

    def __init__(self, **_):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def _stop(self, request):
        CapturingJudge.requests.append(request)
        raise cli.JudgeError("stopped by the test")

    label_check = measure = _stop


@pytest.fixture
def captured(monkeypatch):
    CapturingJudge.requests = []
    monkeypatch.setattr(cli, "JudgeClient", CapturingJudge)
    return CapturingJudge.requests


def test_the_data_check_command_sends_only_rungs_0_to_3(captured):
    args = Namespace(backend="mock", trials=1, cassette=None, judge_dir=None)
    cli.cmd_data_check(args)
    assert [spec.key for spec in captured[0].measure.targets] == EARLIER_KEYS


@pytest.mark.parametrize("last_rung", [3, 4, 5])
def test_the_baseline_measures_rungs_only_up_to_the_last_one_asked_for(
    captured, tmp_path, last_rung
):
    args = Namespace(
        out=tmp_path,
        backend="mock",
        trials=1,
        profile="clean",
        cassette=None,
        replicates=None,
        judge_dir=None,
        last_rung=last_rung,
    )
    cli.cmd_baseline(args)
    assert captured[0].targets == list(ladder.LADDER[: last_rung + 1])
