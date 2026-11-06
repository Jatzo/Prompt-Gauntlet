"""Tool signatures: a target option added after part 1 that must leave every ladder rung untouched.

Part 1 found the open model rarely guessed `read_email`'s `id` argument, because the target is shown
tool names only. `tool_help="signatures"` shows each tool's arguments. The ladder's requests are
pinned by digest: if they moved, every cached answer for rungs 0 to 5 would miss and run again.
"""

import hashlib
import json

from fakes import MemoryEvalCache
from pydantic import TypeAdapter

from arena.config import DEFAULTS
from arena.schemas import TargetAction, TargetKey, TargetPlan
from arena.simulated import SimulatedBackend
from arena.target import app, ladder
from arena.target._tools import TOOL_SIGNATURES, ToolBox
from arena.target.arms import NoDefence, PlanThenExecute
from arena.target.sim import target_policy
from arena.target.suites import ALL_TOOLS, benign_cases

# Every rung's act and plan requests for every benign task, taken before signatures were added.
LADDER_REQUESTS_DIGEST = "b0a7d7f7ec82ba9a"


def test_every_ladder_rung_renders_the_same_requests_as_before():
    digest = hashlib.sha256()
    for rung in ladder.LADDER:
        for case in benign_cases(DEFAULTS.seed, rung.tools):
            episode = app._Episode(case, 0, ToolBox(case.world, case.exposed_tools))
            for tool, schema in (
                ("act", TargetAction.model_json_schema()),
                ("plan", TargetPlan.model_json_schema()),
            ):
                request = app._render(
                    episode, tool, schema, DEFAULTS, obliging=rung.prompt == "obliging"
                )
                digest.update(request.system.encode())
                digest.update(request.user.encode())
    assert digest.hexdigest()[:16] == LADDER_REQUESTS_DIGEST


def test_no_ladder_rung_shows_signatures_and_the_signature_keys_are_valid():
    assert all(rung.tool_help == "names" for rung in ladder.LADDER)
    for rung in (ladder.LADDER[3], ladder.LADDER[5]):
        spec = rung.model_copy(update={"tool_help": "signatures"})
        assert spec.key == f"{rung.key}.signatures"
        assert TypeAdapter(TargetKey).validate_python(spec.key) == spec.key


def test_a_signatures_target_is_shown_the_arguments_of_its_exposed_tools_only():
    seen = []
    policy = target_policy(obey=0.0, complete=1.0, seed=1)

    def recording(request, rng):
        seen.append((request.tool, json.loads(request.user)["tools"]))
        return policy(request, rng)

    target = ladder.LADDER[3].model_copy(update={"tool_help": "signatures"})
    cases = benign_cases(DEFAULTS.seed, target.tools)
    app.run_episodes(
        cases,
        target=target,
        defence=PlanThenExecute(),
        trials=1,
        cache=MemoryEvalCache(),
        backend=SimulatedBackend({"target_open": recording}, seed=1),
    )
    assert {tool for tool, _ in seen} == {"plan", "act"}
    exposed = [sorted(case.exposed_tools) for case in cases]
    for _, tools in seen:
        assert sorted(tools) in exposed
        assert all(tools[name] == TOOL_SIGNATURES[name] for name in tools)


def test_each_signature_names_the_arguments_its_tool_reads():
    assert set(TOOL_SIGNATURES) == ALL_TOOLS
    world = benign_cases(DEFAULTS.seed, "permissive")[0].world
    box = ToolBox(world, frozenset(ALL_TOOLS))
    email = world.inbox[0]
    [segment] = box.run("read_email", {"id": email.id})
    assert segment.id == f"read_email:{email.id}"
    assert set(TOOL_SIGNATURES["send_message"]) >= {"to", "body"}


def test_a_guided_target_is_told_its_turns_left_about_repeats_and_who_it_sent_to():
    """A scripted target reads e1 twice, sends once, then answers: what it sees each turn."""
    script = [
        {"tool": "read_email", "args": {"id": "e1"}},
        {"tool": "read_email", "args": {"id": "e1"}},
        {"tool": "send_message", "args": {"to": "sam@example.invalid", "body": "Thursday"}},
        {"final": "Done."},
    ]
    seen = []

    def scripted(request, rng):
        state = json.loads(request.user)
        seen.append(state)
        return "act", json.dumps(script[len(seen) - 1])

    target = ladder.LADDER[3].model_copy(update={"tool_help": "guided"})
    case = next(c for c in benign_cases(DEFAULTS.seed, target.tools) if c.id == "email-forward")
    [result] = app.run_episodes(
        [case],
        target=target,
        defence=NoDefence(),
        trials=1,
        cache=MemoryEvalCache(),
        backend=SimulatedBackend({"target_open": scripted}, seed=1),
    )
    assert [state["turns_left"] for state in seen] == [6, 5, 4, 3]
    assert seen[0]["tools"] == {name: TOOL_SIGNATURES[name] for name in case.exposed_tools}
    results = [entry["result"] for entry in seen[-1]["history"]]
    assert "Thursday" in results[0][0]
    assert results[1] == [app.REPEAT_NOTICE]
    assert results[2] == [f"Message sent to sam@example.invalid. {app.SENT_NOTICE}"]
    assert result.turns == 4 and result.outcome.task_completed


def test_a_guided_key_is_valid():
    spec = ladder.LADDER[3].model_copy(update={"tool_help": "guided"})
    assert spec.key == "target_open.strict.standard.guided"
    assert TypeAdapter(TargetKey).validate_python(spec.key) == spec.key
