import sqlite3

import pytest

from arena import db
from arena.config import ArenaConfig
from arena.memory.memory import (
    EPISODE_KINDS,
    PRIVATE_EPISODE_KINDS,
    Memory,
    MemoryWriteRejected,
    token_set_jaccard,
)
from arena.schemas import LessonProposal, Prediction

WHERE = {"cycle_id": 1, "step": "postmortem", "role": "ceo"}


@pytest.fixture
def conn(tmp_path):
    connection = db.connect(tmp_path / "arena.db")
    yield connection
    connection.close()


def episode(memory, cycle_id=1):
    return memory.record_episode(
        kind="plan", body={"result": "x"}, **dict(WHERE, cycle_id=cycle_id)
    )


def lesson(evidence, text="Encoded payloads evade literal rules."):
    return LessonProposal(
        text=text, scope_tags=["rules"], evidence_experiment_ids=evidence, confidence=0.6
    )


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608


def test_writes_outside_a_transaction_are_refused(conn):
    with pytest.raises(RuntimeError):
        Memory(conn).record_episode(kind="x", body={}, **WHERE)


def test_the_episode_kinds_are_pinned_and_the_private_ones_are_among_them():
    # Adding a kind is a decision about whether agents may read it, so it fails here first.
    assert EPISODE_KINDS == (
        "plan",
        "briefing",
        "shortlist",
        "postmortem",
        "judge_report",
        "attack_batch",
        "novelty_closed",
        "patch",
        "control_move",
    )
    assert set(PRIVATE_EPISODE_KINDS) <= set(EPISODE_KINDS)
    # A patch's literal rules can quote an evasion, so no agent may read one back.
    assert "patch" in PRIVATE_EPISODE_KINDS


def test_an_unknown_episode_kind_is_rejected_and_nothing_is_written(conn):
    memory = Memory(conn)
    with pytest.raises(MemoryWriteRejected, match="Unknown episode kind"), db.transaction(conn):
        memory.record_episode(kind="experiment", body={}, **WHERE)
    assert count(conn, "memory_episodic") == 0
    assert count(conn, "memory_provenance") == 0


def test_a_lesson_backed_by_a_real_experiment_is_stored_with_provenance(conn):
    memory = Memory(conn)
    with db.transaction(conn):
        evidence = episode(memory)
        lesson_id = memory.add_lesson(lesson([evidence]), **WHERE)
    row = conn.execute(
        "SELECT role, cycle_id, step FROM memory_provenance WHERE table_name = 'memory_lessons'"
        " AND row_id = ?",
        (lesson_id,),
    ).fetchone()
    assert tuple(row) == ("ceo", 1, "postmortem")


def test_a_lesson_citing_a_missing_experiment_is_rejected(conn):
    memory = Memory(conn)
    with pytest.raises(MemoryWriteRejected), db.transaction(conn):
        memory.add_lesson(lesson([999]), **WHERE)
    assert count(conn, "memory_lessons") == 0


def test_a_lesson_without_evidence_cannot_even_be_proposed():
    with pytest.raises(ValueError):
        lesson([])


def test_lessons_are_capped(conn):
    memory = Memory(conn, ArenaConfig(lesson_cap=2, memory_lessons_per_cycle=10))
    with db.transaction(conn):
        evidence = episode(memory)
        memory.add_lesson(lesson([evidence]), **WHERE)
        memory.add_lesson(lesson([evidence]), **WHERE)
    with pytest.raises(MemoryWriteRejected), db.transaction(conn):
        memory.add_lesson(lesson([evidence]), **WHERE)
    assert count(conn, "memory_lessons") == 2


def test_lesson_writes_are_rate_limited_per_cycle(conn):
    memory = Memory(conn, ArenaConfig(memory_lessons_per_cycle=1))
    with db.transaction(conn):
        evidence = episode(memory)
        memory.add_lesson(lesson([evidence]), **WHERE)
    with pytest.raises(MemoryWriteRejected), db.transaction(conn):
        memory.add_lesson(lesson([evidence]), **WHERE)
    with db.transaction(conn):
        memory.add_lesson(lesson([evidence]), **dict(WHERE, cycle_id=2))


def test_backlog_writes_are_rate_limited_per_cycle(conn):
    memory = Memory(conn, ArenaConfig(memory_backlog_per_cycle=2))
    with db.transaction(conn):
        memory.add_backlog_item("Decode base64 before rules.", **WHERE)
        memory.add_backlog_item("Fold homoglyphs before the classifier.", **WHERE)
    with pytest.raises(MemoryWriteRejected), db.transaction(conn):
        memory.add_backlog_item("Split payloads across email fields.", **WHERE)


def test_a_near_duplicate_backlog_item_is_rejected(conn):
    memory = Memory(conn)
    with db.transaction(conn):
        memory.add_backlog_item("Decode base64 before the rules layer runs.", **WHERE)
    with pytest.raises(MemoryWriteRejected), db.transaction(conn):
        memory.add_backlog_item(
            "decode BASE64 before the rules layer runs", **dict(WHERE, cycle_id=2)
        )


def test_a_near_duplicate_with_a_justification_is_accepted(conn):
    memory = Memory(conn)
    with db.transaction(conn):
        memory.add_backlog_item("Decode base64 before the rules layer runs.", **WHERE)
        memory.add_backlog_item(
            "Decode base64 before the rules layer runs.",
            justification="Retest after the classifier prompt changed.",
            **WHERE,
        )
    assert count(conn, "memory_backlog") == 2


def test_a_genuinely_different_backlog_item_is_accepted(conn):
    memory = Memory(conn)
    with db.transaction(conn):
        memory.add_backlog_item("Decode base64 before the rules layer runs.", **WHERE)
        memory.add_backlog_item("Fold homoglyphs before the classifier sees text.", **WHERE)
    assert count(conn, "memory_backlog") == 2


def test_jaccard_ignores_case_and_punctuation():
    assert token_set_jaccard("Decode base64, first.", "decode BASE64 first") == 1.0
    assert token_set_jaccard("a b", "c d") == 0.0


def test_a_prediction_is_stored(conn):
    with db.transaction(conn):
        Memory(conn).record_prediction(Prediction(expected_delta=-0.05, confidence=0.6), **WHERE)
    assert count(conn, "memory_predictions") == 1


def test_operator_notes_are_stored_but_never_editable(conn):
    with db.transaction(conn):
        Memory(conn).add_operator_note("Look at translated benign text.")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE memory_operator_notes SET text = 'changed'")


def test_a_rejected_write_leaves_the_rest_of_the_transaction_unwritten(conn):
    memory = Memory(conn)
    with pytest.raises(MemoryWriteRejected), db.transaction(conn):
        episode(memory)
        memory.add_lesson(lesson([999]), **WHERE)
    assert count(conn, "memory_episodic") == 0
    assert count(conn, "memory_provenance") == 0


def test_an_episode_from_a_rolled_back_cycle_is_not_evidence(conn):
    memory = Memory(conn)
    conn.execute(
        "INSERT INTO cycles (id, run_id, state, created_at, updated_at)"
        " VALUES (1, 'run', 'rolled_back', ?, ?)",
        (db.now(), db.now()),
    )
    with db.transaction(conn):
        evidence = episode(memory)
    with pytest.raises(MemoryWriteRejected), db.transaction(conn):
        memory.add_lesson(lesson([evidence]), **dict(WHERE, cycle_id=2))
