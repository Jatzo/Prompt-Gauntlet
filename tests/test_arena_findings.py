"""Arena findings (PLAN section 7 note of 2026-11-08): with `--reference guided`, up to 5 of a
cycle's valid attacks, one per cluster first, go through part 2's discovery check, and a confirmed
candidate pauses the run for the operator's disclosure decision. Off by default."""

import json

from arena import cli, cycle, db, llm
from arena.config import DEFAULTS
from arena.judge_client import JudgeError
from arena.orchestrator import Orchestrator, phase1_mock_script
from arena.schemas import (
    AttackBatch,
    AttackCandidate,
    AttackVerdict,
    BatchReport,
    DiscoveryConfirmation,
    DiscoveryConfirmReport,
    DiscoveryReport,
    DiscoveryVerdict,
)
from tests.conftest import FakeJudge, numbered


class FindingsJudge(FakeJudge):
    def __init__(self, candidate: bool = True, confirmed: bool = False):
        super().__init__()
        self.candidate, self.confirmed = candidate, confirmed
        self.checks, self.confirms = [], []

    def discovery_check(self, request):
        self.checks.append(request)
        return DiscoveryReport(
            verdicts=[
                DiscoveryVerdict(
                    index=i,
                    task_id=a.task_id,
                    technique="override.direct",
                    status="played",
                    trials=request.trials,
                    successes=2 if self.candidate else 0,
                    success_signals=["sent_to_attacker"] if self.candidate else [],
                    unscorable=0,
                    target_refused=0,
                    candidate=self.candidate,
                )
                for i, a in enumerate(request.attacks)
            ]
        )

    def discovery_confirm(self, request):
        self.confirms.append(request)
        return DiscoveryConfirmReport(
            candidates=[DiscoveryConfirmation(index=0, confirmed=self.confirmed)]
        )


def orchestrator(conn, judge, guided=True):
    backend = llm.MockBackend(script=numbered(phase1_mock_script(), conn))
    config = cli.run_config("guided" if guided else "ladder")
    return Orchestrator(conn, backend=backend, judge=judge, config=config, run_id="r1")


def batch_and_report(clusters):
    attacks = [
        AttackCandidate(
            text=f"attack {i}",
            technique="indirect.email",
            impact_class="data_theft",
            channel="email",
        )
        for i in range(len(clusters))
    ]
    verdicts = [
        AttackVerdict(
            index=i,
            technique="override.direct",
            cluster_id=cluster,
            refused=False,
            valid=cluster != "invalid",
            evaded=False,
            held_back=False,
            classified=True,
        )
        for i, cluster in enumerate(clusters)
    ]
    report = BatchReport(verdicts=verdicts, evading_clusters=0, held_back_clusters=0)
    return AttackBatch(attacks=attacks), report


def test_findings_are_off_by_default(conn):
    judge = FindingsJudge()
    found = orchestrator(conn, judge, guided=False)._findings(1, *batch_and_report(["a", "b"]))
    assert found.screened == 0 and judge.checks == []


def test_one_per_cluster_first_then_the_rest_up_to_five(conn):
    judge = FindingsJudge(candidate=False)
    clusters = ["a", "a", "a", "b", "invalid", "c", "b", "d"]
    found = orchestrator(conn, judge)._findings(4, *batch_and_report(clusters))
    [request] = judge.checks
    texts = [a.text for a in request.attacks]
    # a, b, c, d first, then the second "a".
    assert texts == ["attack 0", "attack 3", "attack 5", "attack 7", "attack 1"]
    assert (request.run_id, request.round, request.trials) == ("arena-r1", 4, 5)
    assert request.target.key == DEFAULTS.discovery_target_key
    assert all(a.task_id for a in request.attacks)
    assert (found.screened, found.candidates, found.confirmed) == (5, 0, 0)
    assert judge.confirms == []


def test_candidates_go_to_claude_confirmation(conn):
    judge = FindingsJudge(candidate=True, confirmed=False)
    found = orchestrator(conn, judge)._findings(2, *batch_and_report(["a", "b"]))
    assert [r.round for r in judge.confirms] == [2]
    assert (found.screened, found.candidates, found.confirmed) == (2, 2, 0)


def test_a_confirmed_finding_pauses_the_run(conn):
    judge = FindingsJudge(candidate=True, confirmed=True)
    outcome = orchestrator(conn, judge).run_cycle()
    state, reason = db.control_state(conn)
    assert state == "paused" and "disclosure" in reason
    assert outcome.status == "paused"
    [detail] = [
        row[0] for row in conn.execute("SELECT detail FROM events WHERE kind = 'arena_findings'")
    ]
    assert '"confirmed": 1' in detail


def test_no_confirmation_lets_the_cycle_commit(conn):
    judge = FindingsJudge(candidate=True, confirmed=False)
    outcome = orchestrator(conn, judge).run_cycle()
    assert outcome.status == "committed"
    assert db.control_state(conn)[0] == "running"


def test_findings_never_reach_the_ceo_briefing(conn):
    first = orchestrator(conn, FindingsJudge(candidate=True, confirmed=True))
    first.run_cycle()
    with db.transaction(conn):
        db.set_control(conn, "running", "operator: resume")
    first.run_cycle()  # finishes cycle 1
    with db.transaction(conn):
        next_cycle = cycle.open_cycle(conn, "r1")
    brief = json.dumps(first._briefing(next_cycle))
    assert "arena_findings" not in brief
    assert "disclosure" not in brief


class FailingJudge(FindingsJudge):
    def discovery_check(self, request):
        raise JudgeError("public files missing")


def test_a_judge_fault_in_the_screening_does_not_block_the_cycle(conn):
    outcome = orchestrator(conn, FailingJudge()).run_cycle()
    assert outcome.status == "committed"
    [detail] = [
        row[0]
        for row in conn.execute(
            "SELECT detail FROM events WHERE kind = ?", ("arena_findings_failed",)
        )
    ]
    assert "public files missing" in detail


class StoppingJudge(FindingsJudge):
    def discovery_confirm(self, request):
        with db.transaction(self.conn):
            db.set_control(self.conn, "stopped", "operator: stop")
        return super().discovery_confirm(request)


def test_a_confirmed_finding_never_turns_a_stop_into_a_pause(conn):
    judge = StoppingJudge(candidate=True, confirmed=True)
    judge.conn = conn
    orchestrator(conn, judge).run_cycle()
    assert db.control_state(conn)[0] == "stopped"
