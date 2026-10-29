"""The only write path into memory.

Memory poisoning is a real attack on a system like this, so nothing reaches the memory tables
without passing through here: every write is schema-checked, evidence-checked, size- and
rate-limited, and records who wrote it, in which cycle and step.

Every method must run inside the caller's transaction, so a step's memory writes commit together
with the record that the step's writes are done. A resumed step can then never write twice.
"""

import hashlib
import json
import re
import sqlite3
from collections.abc import Sequence

from arena import db, novelty
from arena.config import DEFAULTS, ArenaConfig
from arena.detector.patch import fingerprint
from arena.schemas import DetectorConfig, LessonProposal, Prediction

_WORD = re.compile(r"\w+")


class MemoryWriteRejected(ValueError):
    """The write broke a memory rule. Nothing was written."""


# How a detector config's status may move. A rejection also rejects every descendant.
_NEXT_STATUS = {
    # A candidate is rejected only by the cascade, when the lineage it was built on is rejected.
    "candidate": frozenset({"not_kept", "kept_provisional", "rejected"}),
    "kept_provisional": frozenset({"kept_reviewed", "rejected"}),
}
_STANDING = ("baseline", "kept_provisional", "kept_reviewed")
# How a lesson's status may move (PLAN section 9). A disputed lesson can be restored by a checkpoint
# rewrite; superseded and retired are final.
_NEXT_LESSON_STATUS = {
    "active": frozenset({"disputed", "superseded", "retired"}),
    "disputed": frozenset({"active", "superseded", "retired"}),
}
# The configs of one run: a config belongs to the run of the cycle that stored it. A config whose
# cycle has no row belongs to run None, so `IS` compares run ids with None as a value.
_IN_RUN = "FROM detector_configs d LEFT JOIN cycles c ON c.id = d.cycle_id WHERE c.run_id IS ?"


def incumbent(conn: sqlite3.Connection, run_id: str | None) -> tuple[int, DetectorConfig] | None:
    """The config the run's next candidate is measured against: its newest one still standing.
    Each run has its own lineage, so two ablation arms in one database never share configs."""
    placeholders = ",".join("?" * len(_STANDING))
    row = conn.execute(
        f"SELECT d.id, d.config {_IN_RUN} AND d.status IN ({placeholders})"  # noqa: S608
        " ORDER BY d.id DESC LIMIT 1",
        (run_id, *_STANDING),
    ).fetchone()
    if row is None:
        return None
    return row[0], DetectorConfig.model_validate_json(row[1])


def lineage(conn: sqlite3.Connection, config_id: int) -> list[int]:
    """The config's ancestry, from itself back to the baseline."""
    chain = []
    current: int | None = config_id
    while current is not None:
        row = conn.execute(
            "SELECT parent_id FROM detector_configs WHERE id = ?", (current,)
        ).fetchone()
        if row is None:
            raise KeyError(f"No detector config {current}.")
        chain.append(current)
        current = row[0]
    return chain


def token_set_jaccard(left: str, right: str) -> float:
    a = set(_WORD.findall(left.lower()))
    b = set(_WORD.findall(right.lower()))
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


# Every kind the episodic log accepts. A new kind is added here on purpose, together with a decision
# on whether agents may read it; `record_episode` refuses anything else.
EPISODE_KINDS = (
    "plan",
    "briefing",
    "shortlist",
    "postmortem",
    "judge_report",
    "attack_batch",
    "novelty_closed",
    "patch",
)

# Episodes that may hold attack text: the Attacker's batches, held-back attacks included, the
# Defender's patches, whose literal rules can quote an evasion, and the CEO's stored briefing, which
# quotes agent text. No briefing, recall or other agent-facing read may select them.
PRIVATE_EPISODE_KINDS = ("attack_batch", "novelty_closed", "patch", "briefing")


class Memory:
    def __init__(self, conn: sqlite3.Connection, config: ArenaConfig = DEFAULTS):
        self.conn = conn
        self.config = config

    def record_episode(self, *, kind: str, body: dict, cycle_id: int, step: str, role: str) -> int:
        """Append to the episodic log. Nothing is ever updated or deleted there."""
        self._require_transaction()
        if kind not in EPISODE_KINDS:
            raise MemoryWriteRejected(f"Unknown episode kind {kind!r}. Known: {EPISODE_KINDS}.")
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

    def record_actual(self, cycle_id: int, actual_delta: float, *, step: str, role: str) -> None:
        """Pair the cycle's prediction with what happened. Set once; a second value is refused."""
        self._require_transaction()
        row = self.conn.execute(
            "SELECT id, actual_delta FROM memory_predictions WHERE cycle_id = ?", (cycle_id,)
        ).fetchone()
        if row is None:
            raise MemoryWriteRejected(f"Cycle {cycle_id} has no prediction to pair.")
        if row[1] is not None:
            raise MemoryWriteRejected(f"Cycle {cycle_id}'s prediction already has its actual.")
        self.conn.execute(
            "UPDATE memory_predictions SET actual_delta = ? WHERE id = ?", (actual_delta, row[0])
        )
        self._provenance("memory_predictions", row[0], role, cycle_id, step)

    def set_lesson_status(
        self, lesson_id: int, status: str, *, cycle_id: int, step: str, role: str
    ) -> None:
        """Move a lesson along its allowed statuses. Only code rules and checkpoints call this."""
        self._require_transaction()
        row = self.conn.execute(
            "SELECT status FROM memory_lessons WHERE id = ?", (lesson_id,)
        ).fetchone()
        if row is None:
            raise MemoryWriteRejected(f"Lesson {lesson_id} does not exist.")
        if status not in _NEXT_LESSON_STATUS.get(row[0], ()):
            raise MemoryWriteRejected(f"Lesson {lesson_id} cannot go from {row[0]} to {status}.")
        self.conn.execute("UPDATE memory_lessons SET status = ? WHERE id = ?", (status, lesson_id))
        self._provenance("memory_lessons", lesson_id, role, cycle_id, step)

    def add_detector_config(
        self,
        config: DetectorConfig,
        *,
        parent_id: int | None,
        cycle_id: int,
        step: str,
        role: str,
    ) -> int:
        """Store a config. Only a run's first may have no parent: it is the run's baseline. A
        parent must belong to the same run."""
        self._require_transaction()
        config = DetectorConfig.model_validate(config.model_dump())
        row = self.conn.execute("SELECT run_id FROM cycles WHERE id = ?", (cycle_id,)).fetchone()
        run_id = row[0] if row else None
        if parent_id is None:
            if self.conn.execute(f"SELECT 1 {_IN_RUN} LIMIT 1", (run_id,)).fetchone():  # noqa: S608
                raise MemoryWriteRejected(
                    "Only a run's first detector config, its baseline, has no parent."
                )
            status = "baseline"
        else:
            if not self.conn.execute(
                f"SELECT 1 {_IN_RUN} AND d.id = ?",  # noqa: S608
                (run_id, parent_id),
            ).fetchone():
                raise MemoryWriteRejected(
                    f"Parent detector config {parent_id} does not exist in this run."
                )
            status = "candidate"
        row_id = self._insert(
            "INSERT INTO detector_configs (parent_id, config, config_hash, status, cycle_id,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                parent_id,
                config.model_dump_json(),
                fingerprint(config),
                status,
                cycle_id,
                db.now(),
            ),
        )
        self._provenance("detector_configs", row_id, role, cycle_id, step)
        return row_id

    def set_detector_status(
        self, config_id: int, status: str, *, cycle_id: int, step: str, role: str
    ) -> list[int]:
        """Move a config to its next status. Rejecting it reverts its lineage: every descendant is
        rejected too. Returns the ids whose status changed."""
        self._require_transaction()
        row = self.conn.execute(
            "SELECT status FROM detector_configs WHERE id = ?", (config_id,)
        ).fetchone()
        if row is None:
            raise MemoryWriteRejected(f"Detector config {config_id} does not exist.")
        if status not in _NEXT_STATUS.get(row[0], ()):
            raise MemoryWriteRejected(
                f"Detector config {config_id} cannot go from {row[0]} to {status}."
            )
        changed = [config_id]
        if status == "rejected":
            changed += [
                descendant
                for (descendant,) in self.conn.execute(
                    "WITH RECURSIVE tree(id) AS ("
                    "SELECT id FROM detector_configs WHERE parent_id = ?"
                    " UNION SELECT d.id FROM detector_configs d JOIN tree ON d.parent_id = tree.id)"
                    " SELECT d.id FROM tree JOIN detector_configs d ON d.id = tree.id"
                    " WHERE d.status IN ('candidate', 'kept_provisional', 'kept_reviewed')",
                    (config_id,),
                )
            ]
        for changed_id in changed:
            self.conn.execute(
                "UPDATE detector_configs SET status = ? WHERE id = ?", (status, changed_id)
            )
            self._provenance("detector_configs", changed_id, role, cycle_id, step)
        return changed

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

    def archive_texts(self, run_id: str) -> list[str]:
        """The run's own archive. A new run starts empty, two runs in one database never see each
        other's, and anything from a rolled-back cycle is left out, since its work was
        abandoned."""
        return [text for _, text in self._archive_rows(run_id)]

    def _archive_rows(self, run_id: str) -> list[tuple[int, str]]:
        return self.conn.execute(
            "SELECT a.id, a.text FROM novelty_archive a JOIN cycles c ON c.id = a.cycle_id"
            " WHERE c.run_id = ? AND c.state != 'rolled_back' ORDER BY a.id",
            (run_id,),
        ).fetchall()

    def lesson_texts(self, ids: Sequence[int]) -> list[str]:
        """The texts of the cited lessons that are still active, in id order. A cited lesson that
        was disputed or retired since is left out, so it cannot keep steering an agent."""
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        return [
            row[0]
            for row in self.conn.execute(
                "SELECT text FROM memory_lessons WHERE status = 'active'"  # noqa: S608
                f" AND id IN ({placeholders}) ORDER BY id",
                list(ids),
            )
        ]

    def duplicate_plan(self, run_id: str, hypothesis: str) -> int | None:
        """The committed cycle of this run whose plan hypothesis this one nearly repeats, if any."""
        rows = self.conn.execute(
            "SELECT t.cycle_id, json_extract(t.body, '$.hypothesis_text') FROM memory_episodic t"
            " JOIN cycles c ON c.id = t.cycle_id"
            " WHERE c.run_id = ? AND c.state = 'committed' AND t.kind = 'plan'",
            (run_id,),
        )
        for cycle_id, existing in rows:
            if token_set_jaccard(hypothesis, existing) >= self.config.backlog_duplicate_jaccard:
                return cycle_id
        return None

    def episode(self, cycle_id: int, kind: str) -> dict | None:
        """The newest episode of one kind for one cycle, or None."""
        row = self.conn.execute(
            "SELECT body FROM memory_episodic WHERE cycle_id = ? AND kind = ? ORDER BY id DESC"
            " LIMIT 1",
            (cycle_id, kind),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def latest_committed_episode(self, run_id: str, kind: str) -> dict | None:
        """The newest episode of one kind from the run's committed cycles, or None."""
        row = self.conn.execute(
            "SELECT e.body FROM memory_episodic e JOIN cycles c ON c.id = e.cycle_id"
            " WHERE c.run_id = ? AND c.state = 'committed' AND e.kind = ?"
            " ORDER BY e.cycle_id DESC, e.id DESC LIMIT 1",
            (run_id, kind),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def offer_to_archive(
        self, items: Sequence[tuple[str, str]], *, cycle_id: int, step: str, role: str
    ) -> int:
        """Add (cluster, text) pairs already picked by `novelty.archive_candidates`, then shrink
        the archive to its cap: the member closest to another member goes first, ties on a hash
        of the text, so the result depends only on the set offered, not its order. Returns the
        archive size."""
        self._require_transaction()
        run_id = self.conn.execute("SELECT run_id FROM cycles WHERE id = ?", (cycle_id,)).fetchone()
        if run_id is None:
            raise KeyError(f"No cycle {cycle_id}: archive rows must belong to a run.")
        for cluster_id, text in items:
            row_id = self._insert(
                "INSERT INTO novelty_archive (cycle_id, cluster_id, text, created_at)"
                " VALUES (?, ?, ?, ?)",
                (cycle_id, cluster_id, text, db.now()),
            )
            self._provenance("novelty_archive", row_id, role, cycle_id, step)
        members = {
            row_id: (text, novelty.grams(text)) for row_id, text in self._archive_rows(run_id[0])
        }
        while len(members) > self.config.novelty_archive_size:

            def crowding(member_id: int) -> tuple[float, str]:
                text, grams = members[member_id]
                others = [g for other, (_, g) in members.items() if other != member_id]
                return novelty.nearest(grams, others), hashlib.sha256(text.encode()).hexdigest()

            dropped = max(members, key=crowding)
            self.conn.execute("DELETE FROM novelty_archive WHERE id = ?", (dropped,))
            del members[dropped]
        return len(members)

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
