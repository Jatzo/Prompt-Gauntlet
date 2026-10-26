"""Defender patches and the lineage of detector configs (Phase 3 step 2)."""

import pytest

from arena import db
from arena.baselines import REGEX_RULES
from arena.config import DEFAULTS
from arena.detector.patch import PatchRefused, apply_patch, fingerprint
from arena.memory.memory import Memory, MemoryWriteRejected, incumbent, lineage
from arena.schemas import DefenderPatch, PatchOp


def patch(*ops):
    return DefenderPatch(ops=[PatchOp(**op) for op in ops], rationale="test")


def test_ops_add_remove_and_replace_list_items_and_the_prompt():
    added = apply_patch(
        REGEX_RULES, patch({"op": "add", "path": "/normalisers/0", "value": "decode_base64"})
    )
    assert added.normalisers[0] == "decode_base64"
    appended = apply_patch(
        REGEX_RULES,
        patch({"op": "add", "path": "/rules/-", "value": {"id": "r-new", "pattern": "exfil"}}),
    )
    assert appended.rules[-1].id == "r-new"
    removed = apply_patch(REGEX_RULES, patch({"op": "remove", "path": "/rules/0"}))
    assert len(removed.rules) == len(REGEX_RULES.rules) - 1
    prompt = apply_patch(
        REGEX_RULES, patch({"op": "replace", "path": "/classifier_prompt", "value": "Rate it."})
    )
    assert prompt.classifier_prompt == "Rate it."
    assert REGEX_RULES.normalisers[0] != "decode_base64"


@pytest.mark.parametrize(
    "op",
    [
        {"op": "add", "path": "/rules/-", "value": {"id": "r-bad", "pattern": "(a+)+"}},
        {"op": "add", "path": "/normalisers/-", "value": "run_python"},
        {"op": "add", "path": "/rules/-", "value": {"id": "ignore-previous", "pattern": "x"}},
        {"op": "remove", "path": "/rules/99"},
        {"op": "replace", "path": "/classifier_prompt", "value": ["not", "text"]},
        {"op": "remove", "path": "/layers"},
        {"op": "replace", "path": "/rules/-", "value": {"id": "r", "pattern": "x"}},
    ],
)
def test_a_patch_that_breaks_a_rule_is_refused(op):
    with pytest.raises(PatchRefused):
        apply_patch(REGEX_RULES, patch(op))


def test_the_rule_and_literal_caps_hold_for_patched_configs():
    many = [
        {
            "op": "add",
            "path": "/rules/-",
            "value": {"id": f"lit-{n}", "pattern": f"w{n}", "literal": True},
        }
        for n in range(DEFAULTS.max_literal_rules + 1)
    ]
    with pytest.raises(PatchRefused, match="literal"):
        apply_patch(
            REGEX_RULES,
            DefenderPatch.model_construct(ops=[PatchOp(**op) for op in many], rationale="x"),
        )


@pytest.mark.parametrize("path", ["/threshold", "/structural_mode", "/rules/0/pattern"])
def test_a_patch_cannot_reach_a_threshold_or_the_structural_arm(path):
    with pytest.raises(ValueError):
        PatchOp(op="replace", path=path, value="x")


@pytest.fixture
def memory(tmp_path):
    conn = db.connect(tmp_path / "arena.db")
    yield Memory(conn)
    conn.close()


def store(memory, config, parent, cycle=1):
    with db.transaction(memory.conn):
        return memory.add_detector_config(
            config, parent_id=parent, cycle_id=cycle, step="s", role="judge"
        )


def status(memory, config_id, to, cycle=1):
    with db.transaction(memory.conn):
        return memory.set_detector_status(config_id, to, cycle_id=cycle, step="s", role="judge")


def test_the_lineage_walks_back_to_the_baseline_and_the_newest_keep_is_the_incumbent(memory):
    baseline = store(memory, REGEX_RULES, None)
    child_config = apply_patch(REGEX_RULES, patch({"op": "remove", "path": "/rules/0"}))
    child = store(memory, child_config, baseline)
    assert incumbent(memory.conn)[0] == baseline
    status(memory, child, "kept_provisional")
    grandchild = store(
        memory, apply_patch(child_config, patch({"op": "remove", "path": "/rules/0"})), child
    )
    assert lineage(memory.conn, grandchild) == [grandchild, child, baseline]
    assert incumbent(memory.conn) == (child, child_config)
    row = memory.conn.execute(
        "SELECT config_hash FROM detector_configs WHERE id = ?", (child,)
    ).fetchone()
    assert row[0] == fingerprint(child_config)


def test_rejecting_a_keep_reverts_its_lineage_and_leaves_not_kept_records_alone(memory):
    baseline = store(memory, REGEX_RULES, None)
    kept = store(
        memory, apply_patch(REGEX_RULES, patch({"op": "remove", "path": "/rules/0"})), baseline
    )
    status(memory, kept, "kept_provisional")
    built_on = store(
        memory, apply_patch(REGEX_RULES, patch({"op": "remove", "path": "/rules/1"})), kept
    )
    status(memory, built_on, "kept_provisional")
    tried = store(
        memory, apply_patch(REGEX_RULES, patch({"op": "remove", "path": "/rules/2"})), kept
    )
    status(memory, tried, "not_kept")
    assert sorted(status(memory, kept, "rejected")) == sorted([kept, built_on])
    assert incumbent(memory.conn)[0] == baseline
    states = dict(memory.conn.execute("SELECT id, status FROM detector_configs"))
    assert states[tried] == "not_kept"


def test_status_moves_outside_the_rules_are_refused(memory):
    baseline = store(memory, REGEX_RULES, None)
    with pytest.raises(MemoryWriteRejected):
        store(memory, REGEX_RULES, None)
    with pytest.raises(MemoryWriteRejected):
        store(memory, REGEX_RULES, 999)
    child = store(memory, REGEX_RULES, baseline)
    with pytest.raises(MemoryWriteRejected):
        status(memory, child, "kept_reviewed")
    with pytest.raises(MemoryWriteRejected):
        status(memory, baseline, "rejected")


def test_every_lineage_write_records_provenance(memory):
    baseline = store(memory, REGEX_RULES, None)
    child = store(memory, REGEX_RULES, baseline)
    status(memory, child, "not_kept")
    rows = memory.conn.execute(
        "SELECT row_id FROM memory_provenance WHERE table_name = 'detector_configs'"
    ).fetchall()
    assert [row[0] for row in rows] == [baseline, child, child]


def test_an_open_candidate_on_a_rejected_lineage_is_rejected_with_it(memory):
    baseline = store(memory, REGEX_RULES, None)
    kept = store(memory, REGEX_RULES, baseline)
    status(memory, kept, "kept_provisional")
    open_candidate = store(memory, REGEX_RULES, kept)
    assert open_candidate in status(memory, kept, "rejected")
    with pytest.raises(MemoryWriteRejected):
        status(memory, open_candidate, "kept_provisional")


def test_the_lineage_of_a_missing_config_is_a_clear_error(memory):
    with pytest.raises(KeyError, match="999"):
        lineage(memory.conn, 999)
