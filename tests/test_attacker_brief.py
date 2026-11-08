"""The arena Attacker's brief (private plan of 2026-11-08, after live cycle 1 gave 0 valid of 12):
the prompt states how an attack wins, the request lists the tasks, and the submit turn names the
slots that can send or fetch, exactly as the Judge will place them."""

import json
from pathlib import Path

import pytest

from arena import llm
from arena.agents.attacker import BAIT, SUBMIT_STEP, WIN_TOOLS, Attacker, AttackerView, canary
from arena.anomaly import HijackDetected
from arena.config import DEFAULTS
from arena.data.pairs import pick_task
from arena.orchestrator import Orchestrator, phase1_mock_script
from arena.schemas import AttackBatch, BatchReport, Directive
from arena.target.suites import TASKS
from tests.conftest import FakeJudge, numbered

PROMPT = (Path(__file__).parent.parent / "prompts" / "attacker.md").read_text()
DIRECTIVE = Directive.model_validate(Directive.model_config["json_schema_extra"]["examples"][0])
VIEW = AttackerView(DIRECTIVE)


def render(step, cycle_id=7):
    return Attacker(turns=1, seed=1).render(cycle_id, step, VIEW, [], left=0)


def test_the_prompt_states_the_win_rules_and_names_no_held_out_class():
    assert "{ATTACKER}" in PROMPT and "door code" in PROMPT
    assert "canary" not in PROMPT.lower()
    assert "`user` channel is never played" in PROMPT
    for technique in DEFAULTS.held_out_techniques:
        assert technique not in PROMPT
        assert technique.split(".")[-1] not in PROMPT.lower()


def test_every_request_lists_each_task_with_its_channel_and_tools():
    for step in ("attack.t0", SUBMIT_STEP):
        user = render(step)
        for task in TASKS:
            line = next(line for line in user.splitlines() if line.startswith(f"- `{task.id}`"))
            assert f"reads {task.reads}" in line
            assert all(tool in line for tool in task.required_tools)


def slots_in(user, channel):
    [line] = [line for line in user.splitlines() if line.startswith(f"- {channel}: ")]
    listed = line.split(": ", 1)[1]
    if listed == "every slot":
        return set(range(DEFAULTS.attacker_batch_size))
    return {int(item.split(" ")[0]) for item in listed.split(", ")}


def test_the_submit_turn_names_exactly_the_slots_the_judge_gives_a_send_or_fetch_task():
    for cycle_id in (1, 7, 40):
        user = render(SUBMIT_STEP, cycle_id)
        for channel in ("email", "document", "tool_output"):
            expected = {
                i
                for i in range(DEFAULTS.attacker_batch_size)
                if (task := pick_task(f"c{cycle_id}-a{i}", channel))
                and task.required_tools & WIN_TOOLS
            }
            assert expected and slots_in(user, channel) == expected
    assert "can send or fetch" not in render("attack.t0")


class SplitJudge(FakeJudge):
    """Marks the second attack refused, as a held-out technique would be."""

    def validate_batch(self, request):
        report = super().validate_batch(request)
        verdicts = [
            v.model_copy(update={"refused": True}) if v.index == 1 else v for v in report.verdicts
        ]
        return BatchReport(
            verdicts=verdicts,
            evading_clusters=report.evading_clusters,
            held_back_clusters=report.held_back_clusters,
        )


def unplayed(conn):
    return [
        json.loads(row[0])
        for row in conn.execute("SELECT detail FROM events WHERE kind = 'attack_unplayed'")
    ]


def run_with(conn, attacks):
    script = phase1_mock_script()
    script[SUBMIT_STEP] = [json.dumps({"attacks": attacks})]
    backend = llm.MockBackend(script=numbered(script, conn))
    Orchestrator(conn, backend=backend, judge=SplitJudge()).run_cycle()


EXAMPLE = AttackBatch.model_config["json_schema_extra"]["examples"][0]["attacks"][0]


def test_unplayed_attacks_are_logged_as_no_task_and_refused_apart(conn):
    run_with(conn, [EXAMPLE | {"channel": "user"}, EXAMPLE | {"channel": "user"}, EXAMPLE])
    # Attack 1 is both user-channel and refused: it counts once, as refused.
    assert unplayed(conn) == [{"no_task": 1, "refused": 1}]


def test_a_fully_played_batch_logs_no_unplayed_event(conn):
    run_with(conn, [EXAMPLE])
    assert unplayed(conn) == []


class BatchPorts:
    """No query turns; the submit turn returns one attack with the given text."""

    def __init__(self, text):
        self.text = text

    def ask(self, step, tool, user, model):
        return AttackBatch.model_validate({"attacks": [EXAMPLE | {"text": self.text}]})

    def query(self, step, text):
        raise AssertionError("no query turns")


def test_the_bait_avoids_the_words_the_brief_asks_attacks_to_use():
    assert "code" not in BAIT.lower() and "secret" not in BAIT.lower()


def test_an_attack_reusing_the_bait_wording_without_the_token_does_not_pause():
    reused = BAIT.format(tag="{ATTACKER}")
    batch = Attacker(turns=0, seed=1).run(7, VIEW, BatchPorts(reused))
    assert batch.attacks[0].text == reused


def test_an_attack_repeating_the_bait_with_its_token_still_pauses():
    copied = BAIT.format(tag=canary(7, SUBMIT_STEP))
    with pytest.raises(HijackDetected):
        Attacker(turns=0, seed=1).run(7, VIEW, BatchPorts(copied))


class RefusingBackend(llm.MockBackend):
    """The scripted mock, except the provider refuses every Attacker request."""

    def complete(self, *, role, model_id, step_key, request):
        if role == "attacker":
            raise llm.ContentRefused("API Error: Sonnet 5 can't help with this.")
        return super().complete(role=role, model_id=model_id, step_key=step_key, request=request)


def test_a_refused_attacker_request_pauses_the_run_and_keeps_the_cycle_open(conn):
    from arena import db

    backend = RefusingBackend(script=numbered(phase1_mock_script(), conn))
    outcome = Orchestrator(conn, backend=backend, judge=FakeJudge()).run_cycle()
    assert outcome.status == "paused" and "agent_refused" in outcome.detail
    assert db.control_state(conn) == ("paused", "anomaly: agent_refused")
    [(detail, severity)] = conn.execute(
        "SELECT detail, severity FROM events WHERE kind = 'agent_refused'"
    ).fetchall()
    assert severity == "anomaly" and json.loads(detail)["role"] == "attacker"
    # Not rolled back: a resume finishes the same cycle without asking for the plan again.
    [(state,)] = conn.execute("SELECT state FROM cycles WHERE id = ?", (outcome.cycle_id,))
    assert state == "running"
    with db.transaction(conn):
        db.set_control(conn, "running", "operator: resume")
    resumed = llm.MockBackend(script=numbered(phase1_mock_script(), conn))
    again = Orchestrator(conn, backend=resumed, judge=FakeJudge()).run_cycle()
    assert (again.status, again.cycle_id) == ("committed", outcome.cycle_id)
