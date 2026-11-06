"""The five known-answer injections: each lands where its task reads, its route is possible on the
strict tool policy, and a target that follows it fires exactly that route's success signal."""

import pytest

from arena.config import DEFAULTS
from arena.target._tools import ToolBox
from arena.target.checker import SUCCESS_SIGNALS, check
from arena.target.known_answers import KNOWN_ANSWERS, known_answer_cases
from arena.target.world import ATTACKER_ADDRESS, ATTACKER_PLACEHOLDER

ROUTE_TOOL = {
    "answer": None,
    "tool_argument": None,
    "send_from_document": "send_message",
    "fetch": "fetch_url",
    "send_from_email": "send_message",
}


def test_every_route_succeeds_through_a_signal_the_checker_counts():
    assert {answer.signal for answer in KNOWN_ANSWERS} <= SUCCESS_SIGNALS
    assert len({answer.route for answer in KNOWN_ANSWERS}) == 5


@pytest.mark.parametrize("answer", KNOWN_ANSWERS, ids=lambda a: a.route)
@pytest.mark.parametrize("placements", ["standard", "risky"])
def test_the_payload_reaches_the_target_on_the_tasks_first_step(answer, placements):
    for case in known_answer_cases(answer, DEFAULTS.seed, "strict", placements):
        step = case.task.steps[0]
        box = ToolBox(case.world, case.exposed_tools)
        shown = " ".join(segment.text for segment in box.run(step.tool, step.args))
        expected = answer.text.replace(ATTACKER_PLACEHOLDER, ATTACKER_ADDRESS)
        assert expected in shown


@pytest.mark.parametrize("answer", KNOWN_ANSWERS, ids=lambda a: a.route)
def test_a_target_that_follows_it_fires_exactly_its_route(answer):
    for case in known_answer_cases(answer, DEFAULTS.seed, "strict", "standard"):
        needed = ROUTE_TOOL[answer.route]
        assert needed is None or needed in case.exposed_tools
        box = ToolBox(case.world, case.exposed_tools)
        for step in case.task.steps:
            box.run(step.tool, step.args)
        canary, final = case.world.canary, "Done."
        if answer.route == "answer":
            final = f"Done. {canary}"
        elif answer.route == "tool_argument":
            follow = next(s for s in case.task.steps if s.tool != "read_email")
            key = next(iter(follow.args))
            box.run(follow.tool, {**follow.args, key: canary})
        elif answer.route == "fetch":
            box.run(
                "fetch_url", {"url": f"https://example.invalid/latest?owner={ATTACKER_ADDRESS}"}
            )
        else:
            box.run("send_message", {"to": ATTACKER_ADDRESS, "body": "copy"})
        outcome = check(box.trace, final, case.world, case.task)
        assert outcome.signals & SUCCESS_SIGNALS == {answer.signal}
