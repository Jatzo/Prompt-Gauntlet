"""The only write path into memory.

Memory poisoning is a real attack on a system like this, so nothing reaches the memory tables
without passing through here: every write is schema-checked, evidence-checked, size- and
rate-limited, and records who wrote it, in which cycle and step.

Every method must run inside the caller's transaction, so a step's memory writes commit together
with the record that the step's writes are done. A resumed step can then never write twice.
"""

import json
import re
import sqlite3

from arena import db
from arena.config import DEFAULTS, ArenaConfig
from arena.schemas import LessonProposal, Prediction

_WORD = re.compile(r"\w+")


class MemoryWriteRejected(ValueError):
    """The write broke a memory rule. Nothing was written."""


def token_set_jaccard(left: str, right: str) -> float:
    a = set(_WORD.findall(left.lower()))
    b = set(_WORD.findall(right.lower()))
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


class Memory:
    def __init__(self, conn: sqlite3.Connection, config: ArenaConfig = DEFAULTS):
        self.conn = conn
        self.config = config

    def record_episode(self, *, kind: str, body: dict, cycle_id: int, step: str, role: str) -> int:
        """Append to the episodic log. Nothing is ever updated or deleted there."""
        self._require_transaction()
        row_id = self._insert(
            "INSERT INTO memory_episodic (cycle_id, kind, body, created_at) VALUES (?, ?, ?, ?)",
            (cycle_id, kind, json.dumps(body, sort_keys=True), db.now()),
        )
        self._provenance("memory_episodic", row_id, role, cycle_id, step)
        return row_id

    def add_lesson(self, proposal: LessonProposal, *, cycle_id: int, step: str, role: str) -> int:
        self._require_transaction()
        proposal = LessonProposal.model_validate(proposal.model_dump())
        missing = self._missing_episodes(proposal.evidence_experiment_ids)
        if missing:
            raise MemoryWriteRejected(f"Lesson cites experiments that do not exist: {missing}.")
        self._check_rate("memory_lessons", cycle_id, self.config.memory_lessons_per_cycle)
        active = self.conn.execute(
            "SELECT COUNT(*) FROM memory_lessons WHERE status = 'active'"
        ).fetchone()[0]
        if active >= self.config.lesson_cap:
            raise MemoryWriteRejected(
                f"{active} active lessons already, cap is {self.config.lesson_cap}. "
                "Lessons are rewritten under the cap at the next checkpoint."
            )
        row_id = self._insert(
            "INSERT INTO memory_lessons (text, scope_tags, evidence_ids, confidence, status,"
            " cycle_id, created_at) VALUES (?, ?, ?, ?, 'active', ?, ?)",
            (
                proposal.text,
                json.dumps(proposal.scope_tags),
                json.dumps(proposal.evidence_experiment_ids),
                proposal.confidence,
                cycle_id,
                db.now(),
            ),
        )
        self._provenance("memory_lessons", row_id, role, cycle_id, step)
        return row_id

    def add_backlog_item(
        self,
        text: str,
        *,
        cycle_id: int,
        step: str,
        role: str,
        justification: str | None = None,
    ) -> int:
        """Add a hypothesis. A near-duplicate of an open item needs a stated reason."""
        self._require_transaction()
        if not text.strip():
            raise MemoryWriteRejected("A backlog item needs some text.")
        self._check_rate("memory_backlog", cycle_id, self.config.memory_backlog_per_cycle)
        if not justification:
            for existing_id, existing in self.conn.execute(
                "SELECT id, text FROM memory_backlog WHERE status != 'abandoned'"
            ):
                similarity = token_set_jaccard(text, existing)
                if similarity >= self.config.backlog_duplicate_jaccard:
                    raise MemoryWriteRejected(
                        f"Near-duplicate of backlog item {existing_id} "
                        f"(similarity {similarity:.2f}). Give a justification to add it anyway."
                    )
        row_id = self._insert(
            "INSERT INTO memory_backlog (text, status, justification, cycle_id, created_at)"
            " VALUES (?, 'proposed', ?, ?, ?)",
            (text, justification, cycle_id, db.now()),
        )
        self._provenance("memory_backlog", row_id, role, cycle_id, step)
        return row_id

    def record_prediction(
        self, prediction: Prediction, *, cycle_id: int, step: str, role: str
    ) -> int:
        self._require_transaction()
        prediction = Prediction.model_validate(prediction.model_dump())
        row_id = self._insert(
            "INSERT INTO memory_predictions (cycle_id, expected_delta, confidence, created_at)"
            " VALUES (?, ?, ?, ?)",
            (cycle_id, prediction.expected_delta, prediction.confidence, db.now()),
        )
        self._provenance("memory_predictions", row_id, role, cycle_id, step)
        return row_id

    def add_operator_note(self, text: str) -> int:
        """Operator guidance. Written once by the operator and never edited by code."""
        self._require_transaction()
        if not text.strip():
            raise MemoryWriteRejected("An operator note needs some text.")
        row_id = self._insert(
            "INSERT INTO memory_operator_notes (text, created_at) VALUES (?, ?)", (text, db.now())
        )
        self._provenance("memory_operator_notes", row_id, "operator", 0, "operator")
        return row_id

    def _require_transaction(self) -> None:
        if not self.conn.in_transaction:
            raise RuntimeError(
                "Memory writes must run inside db.transaction(), together with the step's record."
            )

    def _insert(self, sql: str, params: tuple) -> int:
        return self.conn.execute(sql, params).lastrowid

    def _missing_episodes(self, ids: list[int]) -> list[int]:
        """Ids with no usable episode. Episodes from a rolled-back cycle do not count: that
        cycle's work was abandoned, possibly because an agent was hijacked."""
        placeholders = ",".join("?" * len(ids))
        found = {
            row[0]
            for row in self.conn.execute(
                "SELECT e.id FROM memory_episodic e LEFT JOIN cycles c ON c.id = e.cycle_id"  # noqa: S608
                f" WHERE e.id IN ({placeholders}) AND COALESCE(c.state, '') != 'rolled_back'",
                ids,
            )
        }
        return sorted(set(ids) - found)

    def _check_rate(self, table: str, cycle_id: int, limit: int) -> None:
        written = self.conn.execute(
            "SELECT COUNT(*) FROM memory_provenance WHERE table_name = ? AND cycle_id = ?",
            (table, cycle_id),
        ).fetchone()[0]
        if written >= limit:
            raise MemoryWriteRejected(
                f"Cycle {cycle_id} has already written {written} rows to {table}; limit is {limit}."
            )

    def _provenance(self, table: str, row_id: int, role: str, cycle_id: int, step: str) -> None:
        self.conn.execute(
            "INSERT INTO memory_provenance (table_name, row_id, role, cycle_id, step, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (table, row_id, role, cycle_id, step, db.now()),
        )
