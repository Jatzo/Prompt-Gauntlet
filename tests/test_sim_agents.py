"""The simulated agents behind the free mock battle (Phase 3 step 14), and the 30-cycle replay."""

import json

import pytest

from arena import db, llm
from arena.agents import defender
from arena.agents.attacker import SUBMIT_STEP
from arena.config import DEFAULTS, REPO_ROOT
from arena.judge_client import JudgeClient
from arena.memory.memory import Memory
from arena.orchestrator import Orchestrator
from arena.schemas import (
    AttackBatch,
    AttackVerdict,
    CEOPlan,
    DefenderPatch,
    DetectorQuery,
    JudgeReport,
    PostMortem,
)
from arena.sim_agents import FOCI, SimAgentsBackend
from arena.target.world import ATTACKER_PLACEHOLDER
from tests.conftest import FakeJudge

STEPS = (
    ("ceo", "plan", "propose_plan", CEOPlan),
    ("attacker", "attack.t0", "query_detector", DetectorQuery),
    ("attacker", SUBMIT_STEP, "submit_attack_batch", AttackBatch),
    ("defender", defender.STEP, defender.TOOL, DefenderPatch),
    ("ceo", "postmortem", "write_postmortem", PostMortem),
)


def answer(backend, role, cycle, step, tool):
    request = llm.LLMRequest(tool=tool, tools=(), system="s", user="u")
    return backend.complete(role=role, model_id="m", step_key=(cycle, step), request=request)


@pytest.mark.parametrize(("role", "step", "tool", "model"), STEPS)
def test_every_answer_is_schema_valid_and_repeats_for_the_same_cycle(role, step, tool, model):
    backend = SimAgentsBackend(seed=7)
    first = answer(backend, role, 3, step, tool)
    model.model_validate_json(first.raw_output)
    assert first.tool == tool
    assert answer(SimAgentsBackend(seed=7), role, 3, step, tool).raw_output == first.raw_output


def test_answers_vary_from_cycle_to_cycle():
    backend = SimAgentsBackend(seed=7)
    for role, step, tool, _ in STEPS[:4]:
        outputs = {answer(backend, role, cycle, step, tool).raw_output for cycle in range(1, 13)}
        assert len(outputs) > 1, step


def test_the_ceo_never_focuses_on_a_held_out_technique_and_runs_both_agents():
    backend = SimAgentsBackend(seed=7)
    for cycle in range(1, 40):
        plan = CEOPlan.model_validate_json(answer(backend, "ceo", cycle, "plan", "p").raw_output)
        assert plan.focus in FOCI
        assert plan.focus not in DEFAULTS.held_out_techniques
        assert plan.agents_to_run == ["attacker", "defender"]


def test_every_payload_names_the_attacker_so_the_target_can_act_on_it():
    backend = SimAgentsBackend(seed=7)
    for cycle in range(1, 20):
        raw = answer(backend, "attacker", cycle, SUBMIT_STEP, "submit_attack_batch").raw_output
        batch = AttackBatch.model_validate_json(raw)
        assert all(ATTACKER_PLACEHOLDER in attack.text for attack in batch.attacks)


def test_a_role_with_no_policy_is_refused():
    with pytest.raises(RuntimeError, match="No simulated agent"):
        answer(SimAgentsBackend(seed=7), "researcher", 1, "research", "x")


def statuses(conn):
    rows = conn.execute("SELECT status FROM detector_configs ORDER BY id").fetchall()
    return [row[0] for row in rows]


def test_a_sim_run_against_the_real_judge_keeps_one_patch_and_rejects_others(conn, built_judge):
    """The keep rule runs for real, on the synthetic folder with the Judge's simulated models."""
    with JudgeClient(REPO_ROOT, built_judge) as judge:
        orchestrator = Orchestrator(conn, backend=SimAgentsBackend(DEFAULTS.seed), judge=judge)
        outcomes = [orchestrator.run_cycle() for _ in range(5)]
    assert [outcome.status for outcome in outcomes] == ["committed"] * 5
    found = statuses(conn)
    assert found.count("kept_provisional") >= 1, found
    assert found.count("not_kept") >= 1, found


class Recorder:
    """Writes each simulated answer to a cassette, as a recording run would."""

    kind = "mock"
    name = "sim-recorder"

    def __init__(self, inner, path):
        self.inner, self.path = inner, path

    def complete(self, *, role, model_id, step_key, request):
        response = self.inner.complete(
            role=role, model_id=model_id, step_key=step_key, request=request
        )
        entry = {
            "role": role,
            "step": step_key[1],
            "tool": response.tool,
            "raw_output": response.raw_output,
            "model_id": response.model_id,
        }
        with self.path.open("a") as out:
            out.write(json.dumps(entry) + "\n")
        return response


EPISODE_MODELS = {
    "plan": CEOPlan,
    "postmortem": PostMortem,
    "judge_report": JudgeReport,
}


def test_a_recorded_30_cycle_sim_run_replays_to_the_same_schema_valid_artifacts(tmp_path):
    cassette = tmp_path / "sim.cassette.jsonl"
    recorded = db.connect(tmp_path / "recorded.db")
    replayed = db.connect(tmp_path / "replayed.db")
    for conn, backend in (
        (recorded, Recorder(SimAgentsBackend(DEFAULTS.seed), cassette)),
        (replayed, None),
    ):
        backend = backend or llm.ReplayBackend(cassette)
        with db.transaction(conn):
            db.set_control(conn, "running", "test")
        orchestrator = Orchestrator(conn, backend=backend, judge=FakeJudge())
        assert [orchestrator.run_cycle().status for _ in range(30)] == ["committed"] * 30

    def outputs(conn):
        rows = conn.execute("SELECT cycle_id, step, raw_output FROM llm_calls ORDER BY id")
        return [tuple(row) for row in rows]

    assert outputs(replayed) == outputs(recorded)
    memory = Memory(replayed)
    for cycle_id in range(1, 31):
        for kind, model in EPISODE_MODELS.items():
            model.model_validate(memory.episode(cycle_id, kind))
        batch = memory.episode(cycle_id, "attack_batch")
        verdicts = [AttackVerdict.model_validate(verdict) for verdict in batch["verdicts"]]
        assert len(verdicts) == len(batch["texts"]) > 0
        DefenderPatch.model_validate(memory.episode(cycle_id, "patch")["patch"])


def test_the_ceo_picks_from_the_shortlist_in_its_prompt():
    backend = SimAgentsBackend(seed=7)
    prompt = "## Focus shortlist (pick one)\n- tool.argument: least tested\n- explore: new\n\nGo."
    request = llm.LLMRequest(tool="propose_plan", tools=(), system="s", user=prompt)
    foci = {
        CEOPlan.model_validate_json(
            backend.complete(
                role="ceo", model_id="m", step_key=(cycle, "plan"), request=request
            ).raw_output
        ).focus
        for cycle in range(1, 20)
    }
    assert foci == {"tool.argument", "explore"}


def test_the_ceo_acknowledges_the_notes_its_prompt_lists():
    backend = SimAgentsBackend(seed=7)
    prompt = "Cycle 3. Operator notes to acknowledge: 2, 5. Call write_postmortem."
    request = llm.LLMRequest(tool="write_postmortem", tools=(), system="s", user=prompt)
    raw = backend.complete(role="ceo", model_id="m", step_key=(3, "postmortem"), request=request)
    assert json.loads(raw.raw_output)["operator_notes_acknowledged"] == [2, 5]
