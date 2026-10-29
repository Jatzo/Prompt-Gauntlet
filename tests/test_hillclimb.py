"""The scripted hill-climb control (arm C): the rule bank, the moves and a control cycle."""

import json
import re

import pytest

from arena import cycle, db, evidence
from arena.baselines import REGEX_RULES
from arena.config import DEFAULTS, REPO_ROOT
from arena.control import hillclimb
from arena.detector.patch import apply_patch, fingerprint
from arena.detector.regex_safety import check_pattern
from arena.judge_client import JudgeClient
from arena.memory.memory import Memory
from arena.orchestrator import Orchestrator
from arena.schemas import Rule
from arena.sim_agents import SimAgentsBackend
from arena.target.world import ATTACKER_ADDRESS, ATTACKER_PLACEHOLDER
from arena.taxonomy import TECHNIQUES
from tests.conftest import FakeJudge


@pytest.mark.parametrize("rule_id, technique, pattern", hillclimb.RULE_BANK)
def test_every_bank_rule_is_safe_known_and_not_a_shortcut(rule_id, technique, pattern):
    check_pattern(pattern)
    assert technique in TECHNIQUES
    assert technique not in DEFAULTS.held_out_techniques
    # The attacker's address marks every simulated attack, so a rule on it would be a shortcut.
    for marker in (ATTACKER_ADDRESS, ATTACKER_PLACEHOLDER.lower(), "attacker@", "example.invalid"):
        assert not re.search(pattern, marker), (rule_id, marker)


def test_bank_rule_ids_are_unique_and_none_clashes_with_the_baseline():
    ids = [rule_id for rule_id, _, _ in hillclimb.RULE_BANK]
    assert len(set(ids)) == len(ids)
    assert not set(ids) & {rule.id for rule in REGEX_RULES.rules}


def test_the_moves_are_every_one_step_change_and_each_changes_the_config():
    found = hillclimb.moves(REGEX_RULES)
    labels = [move.label for move in found]
    assert len(set(labels)) == len(labels)
    absent = set(hillclimb.NORMALISERS) - set(REGEX_RULES.normalisers)
    assert {f"add normaliser {name}" for name in absent} <= set(labels)
    assert {f"remove normaliser {name}" for name in REGEX_RULES.normalisers} <= set(labels)
    assert {f"remove rule {rule.id}" for rule in REGEX_RULES.rules} <= set(labels)
    assert {f"add rule {rule_id}" for rule_id, _, _ in hillclimb.RULE_BANK} <= set(labels)
    before = fingerprint(REGEX_RULES)
    assert all(fingerprint(apply_patch(REGEX_RULES, m.patch)) != before for m in found)


def test_a_config_with_no_rules_layer_gets_no_rule_moves():
    config = REGEX_RULES.model_copy(update={"layers": ["normalise"], "rules": []})
    assert not [m for m in hillclimb.moves(config) if "rule" in m.label]


def test_a_move_the_patch_caps_refuse_is_never_offered():
    # An incumbent already at the rule cap: adding any rule would be refused.
    full = [{"id": f"cap-{i}", "pattern": f"capword{i}"} for i in range(DEFAULTS.max_rules)]
    config = REGEX_RULES.model_copy(update={"rules": [Rule(**r) for r in full]})
    labels = [m.label for m in hillclimb.moves(config)]
    assert not [label for label in labels if label.startswith("add rule")]
    assert "remove rule cap-0" in labels


def test_the_focus_techniques_rules_come_first_and_tried_moves_are_skipped():
    first = hillclimb.next_move(REGEX_RULES, "override.direct", [], seed=1)
    assert first.move.label == "add rule hc-override"
    second = hillclimb.next_move(REGEX_RULES, "override.direct", [first.move.label], seed=1)
    assert second.move.label != first.move.label
    assert not second.restarted


def test_once_every_move_is_tried_the_order_starts_again():
    every = [m.label for m in hillclimb.moves(REGEX_RULES)]
    choice = hillclimb.next_move(REGEX_RULES, "explore", every, seed=1)
    assert choice.restarted
    assert choice.move is not None


def test_tried_moves_count_only_against_the_same_incumbent_and_reset_on_a_restart():
    parent = fingerprint(REGEX_RULES)
    history = [
        {"label": "a", "parent": parent, "restarted": False},
        {"label": "b", "parent": "another config", "restarted": False},
        {"label": "c", "parent": parent, "restarted": False},
    ]
    assert hillclimb.tried_since_restart(history, REGEX_RULES) == {"a", "c"}
    history.append({"label": "d", "parent": parent, "restarted": True})
    assert hillclimb.tried_since_restart(history, REGEX_RULES) == {"d"}


class AttackerOnly(SimAgentsBackend):
    """The simulated Attacker. Asking the CEO or the Defender fails the test."""

    def complete(self, *, role, model_id, step_key, request):
        if role != "attacker":
            raise AssertionError(f"The control arm asked the {role}.")
        return super().complete(role=role, model_id=model_id, step_key=step_key, request=request)


def control(conn, judge=None, run_id="control"):
    return Orchestrator(
        conn,
        backend=AttackerOnly(DEFAULTS.seed),
        judge=judge or FakeJudge(),
        run_id=run_id,
        arm="control",
    )


def kinds(conn, cycle_id):
    rows = conn.execute("SELECT kind FROM memory_episodic WHERE cycle_id = ?", (cycle_id,))
    return [row[0] for row in rows]


def test_a_control_cycle_asks_no_ceo_or_defender_and_writes_no_lesson_or_prediction(conn):
    outcome = control(conn).run_cycle()
    assert outcome.status == "committed", outcome.detail
    found = kinds(conn, outcome.cycle_id)
    for kind in ("shortlist", "plan", "control_move", "attack_batch", "patch", "judge_report"):
        assert kind in found
    assert "postmortem" not in found and "briefing" not in found
    assert conn.execute("SELECT COUNT(*) FROM memory_lessons").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM memory_predictions").fetchone()[0] == 0
    plan = Memory(conn).episode(outcome.cycle_id, "plan")
    assert plan["prediction"] is None
    assert plan["hypothesis_text"] == f"Control cycle {outcome.cycle_id}: {plan['focus']}."
    roles = {
        row[0]
        for row in conn.execute(
            "SELECT role FROM memory_provenance WHERE cycle_id = ? AND step IN ('plan', 'defend')",
            (outcome.cycle_id,),
        )
    }
    assert roles == {"orchestrator"}


def test_the_plan_names_no_move_so_the_attacker_cannot_read_it(conn):
    outcome = control(conn).run_cycle()
    move = Memory(conn).episode(outcome.cycle_id, "control_move")
    plan = Memory(conn).episode(outcome.cycle_id, "plan")
    assert move["label"] not in plan["hypothesis_text"]


def test_the_defend_step_applies_the_move_chosen_at_plan_time(conn):
    orchestrator = control(conn)
    outcome = orchestrator.run_cycle()
    move = Memory(conn).episode(outcome.cycle_id, "control_move")
    candidate = conn.execute(
        "SELECT config FROM detector_configs WHERE cycle_id = ? AND parent_id IS NOT NULL",
        (outcome.cycle_id,),
    ).fetchone()[0]
    expected = apply_patch(REGEX_RULES, hillclimb.DefenderPatch.model_validate(move["patch"]))
    assert json.loads(candidate) == expected.model_dump(mode="json")


def test_the_focus_rotates_over_each_cycles_shortlist(conn):
    orchestrator = control(conn, judge=FakeJudge(keep=False))
    for done in range(4):
        outcome = orchestrator.run_cycle()
        entries = Memory(conn).episode(outcome.cycle_id, "shortlist")["entries"]
        foci = [focus for _, focus in entries]
        plan = Memory(conn).episode(outcome.cycle_id, "plan")
        assert plan["focus"] == foci[done % len(foci)]


def test_a_rejected_move_is_not_tried_again_against_the_same_incumbent(conn):
    orchestrator = control(conn, judge=FakeJudge(keep=False))
    labels = []
    for _ in range(3):
        outcome = orchestrator.run_cycle()
        assert outcome.status == "committed", outcome.detail
        labels.append(Memory(conn).episode(outcome.cycle_id, "control_move")["label"])
    assert len(set(labels)) == 3


def test_a_repeated_plan_step_stores_one_move(conn):
    orchestrator = control(conn)
    cycle_id = cycle.open_cycle(conn, "control")
    orchestrator._check_hashes_and_write_manifest(cycle_id)
    orchestrator._step_plan(cycle_id)
    orchestrator._step_plan(cycle_id)
    assert kinds(conn, cycle_id).count("control_move") == 1


def test_a_run_cannot_change_arm_part_way(conn):
    assert control(conn, run_id="one-arm").run_cycle().status == "committed"
    other = Orchestrator(
        conn, backend=SimAgentsBackend(DEFAULTS.seed), judge=FakeJudge(), run_id="one-arm"
    )
    outcome = other.run_cycle()
    assert outcome.status == "paused"
    assert "config_mismatch" in outcome.detail


def test_a_run_from_before_arms_were_recorded_still_cannot_mix_arms(conn):
    with db.transaction(conn):
        old = cycle.open_cycle(conn, "legacy")
        conn.execute(
            "INSERT INTO manifests (run_id, cycle_id, model_ids, seed, config_hash, git_sha,"
            " constitution_hash, created_at) VALUES ('legacy', ?, '{}', 1, 'h', 'g', 'c', 't')",
            (old,),
        )
        cycle.advance(conn, old, "rolled_back")
    assert control(conn, run_id="legacy").run_cycle().status == "committed"
    full = Orchestrator(
        conn, backend=SimAgentsBackend(DEFAULTS.seed), judge=FakeJudge(), run_id="legacy"
    )
    outcome = full.run_cycle()
    assert outcome.status == "paused" and "config_mismatch" in outcome.detail


def test_a_crash_between_the_shortlist_and_the_plan_resumes_with_the_same_move(conn, monkeypatch):
    orchestrator = control(conn)
    cycle_id = cycle.open_cycle(conn, "control")
    orchestrator._check_hashes_and_write_manifest(cycle_id)
    real = Memory.record_episode

    def crash_on_the_move(self, *, kind, **rest):
        if kind == "control_move":
            raise RuntimeError("crash")
        return real(self, kind=kind, **rest)

    monkeypatch.setattr(Memory, "record_episode", crash_on_the_move)
    with pytest.raises(RuntimeError):
        orchestrator._step_plan(cycle_id)
    assert kinds(conn, cycle_id) == ["shortlist"]
    monkeypatch.setattr(Memory, "record_episode", real)
    control(conn)._step_plan(cycle_id)
    assert kinds(conn, cycle_id).count("shortlist") == 1
    entries = Memory(conn).episode(cycle_id, "shortlist")["entries"]
    focus = entries[0][1]
    expected = hillclimb.next_move(REGEX_RULES, focus, [], DEFAULTS.seed + cycle_id)
    assert Memory(conn).episode(cycle_id, "plan")["focus"] == focus
    assert Memory(conn).episode(cycle_id, "control_move")["label"] == expected.move.label


def test_the_manifest_records_the_arm_and_the_bank(conn):
    outcome = control(conn).run_cycle()
    row = conn.execute(
        "SELECT arm, control_bank_hash FROM manifests WHERE cycle_id = ?", (outcome.cycle_id,)
    ).fetchone()
    assert (row["arm"], row["control_bank_hash"]) == ("control", hillclimb.bank_hash())


def test_a_control_run_exports_without_a_postmortem_or_a_prediction(conn, tmp_path):
    control(conn).run_cycle()
    pack = evidence.build(conn, "control")
    record = pack.private[0]
    assert record["postmortem"] is None
    assert record["manifest"]["arm"]["value"] == "control"
    assert record["plan"]["expected_delta"]["value"] is None
    evidence.write(pack, tmp_path / "evidence")
    for half in ("public", "private"):
        report = (tmp_path / "evidence" / half / "report.md").read_text()
        assert "Scripted control: no prediction." in report


def test_a_control_run_against_the_real_judge_judges_a_real_candidate_every_cycle(
    conn, built_judge
):
    """The keep rule runs for real, on the synthetic folder with the Judge's simulated models.

    Nothing is required to be kept: the folder's dev partition holds two attack families, one per
    fold, so a one-step move aimed at one family cannot replicate on the other fold."""
    with JudgeClient(REPO_ROOT, built_judge) as judge:
        orchestrator = control(conn, judge=judge)
        outcomes = [orchestrator.run_cycle() for _ in range(4)]
    assert [outcome.status for outcome in outcomes] == ["committed"] * 4, outcomes
    for outcome in outcomes:
        report = Memory(conn).episode(outcome.cycle_id, "judge_report")
        assert report["decision"] in ("keep", "reject")
        assert report["reason_code"] != "not_implemented"
    statuses = [row[0] for row in conn.execute("SELECT status FROM detector_configs")]
    assert statuses.count("not_kept") + statuses.count("kept_provisional") == 4, statuses
