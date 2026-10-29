"""The dashboard score, memory and operations panels, read from one run (PLAN section 15).

Like `arena_feed`, every builder takes a read-only connection the caller opens, reads the agent
database only (it holds no test numbers), and scopes to one run: the one asked for, or the run of
the newest cycle.

- `scores`: per committed cycle, the Judge's dev aggregates with their intervals, the decision, and
  the candidate's standing. Numbers and codes only.
- `memory`: the latest plan and the exact briefing the CEO was sent, lessons, the open backlog and
  the prediction pairs. This is the one panel that carries agent text, which may quote an attack;
  the page shows it as plain text, never as markup.
- `ops`: control state, recent anomalies, usage per role and the operator notes.
"""

import json
import re
import sqlite3

from arena.config import DEFAULTS
from arena.evidence import backend_of, technique_code
from arena.memory import calibration

RECENT_ANOMALIES = 20
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_CATEGORY = re.compile(r"[a-z][a-z_]{0,39}")
_DECISIONS = ("keep", "reject", "none")
_STANDINGS = ("not_kept", "kept_provisional", "kept_reviewed", "rejected")


def runs(conn: sqlite3.Connection) -> list[str]:
    """Every run in the database, newest first by its latest cycle."""
    rows = conn.execute("SELECT run_id FROM cycles GROUP BY run_id ORDER BY MAX(id) DESC")
    return [row[0] for row in rows]


def pick_run(conn: sqlite3.Connection, run_id: str | None) -> str | None:
    """The run asked for if the database holds it, else the run of the newest cycle."""
    known = runs(conn)
    if run_id in known:
        return run_id
    return known[0] if known else None


def _code(value: object, pattern: re.Pattern[str] = _IDENTIFIER) -> str:
    return value if isinstance(value, str) and pattern.fullmatch(value) else "other"


def _metric(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    parts = {key: value.get(key) for key in ("value", "ci_low", "ci_high")}
    if not all(isinstance(part, int | float) for part in parts.values()):
        return None
    return {key: float(part) for key, part in parts.items()}


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) else None


def _episode(conn: sqlite3.Connection, cycle_id: int, kind: str) -> dict | None:
    row = conn.execute(
        "SELECT body FROM memory_episodic WHERE cycle_id = ? AND kind = ? ORDER BY id DESC LIMIT 1",
        (cycle_id, kind),
    ).fetchone()
    return json.loads(row[0]) if row else None


def scores(conn: sqlite3.Connection, run_id: str) -> dict:
    rows = conn.execute(
        "SELECT id FROM cycles WHERE run_id = ? AND state = 'committed' ORDER BY id", (run_id,)
    ).fetchall()
    points = []
    for (cycle_id,) in rows:
        report = _episode(conn, cycle_id, "judge_report")
        if report is None:
            continue
        standing = conn.execute(
            "SELECT status FROM detector_configs WHERE cycle_id = ? AND parent_id IS NOT NULL"
            " ORDER BY id DESC LIMIT 1",
            (cycle_id,),
        ).fetchone()
        categories = report.get("per_category_fpr")
        points.append(
            {
                "cycle": cycle_id,
                "backend": backend_of(conn, cycle_id)[0],
                "decision": report.get("decision")
                if report.get("decision") in _DECISIONS
                else "none",
                "reason": _code(report.get("reason_code")),
                "standing": standing[0] if standing and standing[0] in _STANDINGS else None,
                "asr": _metric(report.get("asr")),
                "utility": _metric(report.get("utility")),
                "tpr": _metric(report.get("tpr_at_target_fpr")),
                "achieved_fpr": _number(report.get("achieved_fpr")),
                "category_fpr": {
                    name: float(value)
                    for name, value in (categories if isinstance(categories, dict) else {}).items()
                    if _CATEGORY.fullmatch(name) and isinstance(value, int | float)
                },
            }
        )
    return {
        "run": run_id,
        "points": points,
        "limits": {
            "target_fpr": DEFAULTS.target_fpr,
            "category_fpr_cap": DEFAULTS.per_category_fpr_cap,
        },
    }


def memory(conn: sqlite3.Connection, run_id: str) -> dict:
    latest = conn.execute(
        "SELECT t.cycle_id, t.body FROM memory_episodic t JOIN cycles c ON c.id = t.cycle_id"
        " WHERE c.run_id = ? AND t.kind = 'briefing' ORDER BY t.id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    briefing = None
    if latest is not None:
        body = json.loads(latest[1])
        briefing = {"cycle": latest[0], "text": str(body.get("text", ""))}
    plan_row = conn.execute(
        "SELECT t.cycle_id, t.body FROM memory_episodic t JOIN cycles c ON c.id = t.cycle_id"
        " WHERE c.run_id = ? AND t.kind = 'plan' ORDER BY t.id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    plan = None
    if plan_row is not None:
        body = json.loads(plan_row[1])
        prediction = body.get("prediction") or {}
        plan = {
            "cycle": plan_row[0],
            "focus": technique_code(str(body.get("focus", ""))),
            "hypothesis": str(body.get("hypothesis_text", "")),
            "expected_delta": _number(prediction.get("expected_delta")),
            "confidence": _number(prediction.get("confidence")),
            "cites": [n for n in body.get("cites_lesson_ids", []) if isinstance(n, int)],
        }
    lessons = [
        {
            "id": row[0],
            "text": row[1],
            "tags": [_code(tag) for tag in json.loads(row[2])],
            "confidence": row[3],
            "status": row[4],
            "evidence_cycles": _evidence_cycles(conn, json.loads(row[5])),
        }
        for row in conn.execute(
            "SELECT t.id, t.text, t.scope_tags, t.confidence, t.status, t.evidence_ids"
            " FROM memory_lessons t JOIN cycles c ON c.id = t.cycle_id"
            " WHERE c.run_id = ? ORDER BY t.id DESC",
            (run_id,),
        )
    ]
    backlog = [
        {"id": row[0], "text": row[1], "status": row[2]}
        for row in conn.execute(
            "SELECT t.id, t.text, t.status FROM memory_backlog t JOIN cycles c ON c.id = t.cycle_id"
            " WHERE c.run_id = ? AND t.status IN ('proposed', 'running') ORDER BY t.id DESC",
            (run_id,),
        )
    ]
    pairs = [
        {"cycle": pair.cycle_id, "expected": pair.expected, "actual": pair.actual}
        for pair in calibration.pairs(conn, run_id)
    ]
    return {
        "run": run_id,
        "plan": plan,
        "briefing": briefing,
        "lessons": lessons,
        "backlog": backlog,
        "calibration": pairs,
    }


def _evidence_cycles(conn: sqlite3.Connection, episode_ids: list) -> list[int]:
    ids = [n for n in episode_ids if isinstance(n, int)]
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT DISTINCT cycle_id FROM memory_episodic WHERE id IN ({placeholders})"  # noqa: S608
        " ORDER BY cycle_id",
        ids,
    )
    return [row[0] for row in rows]


def ops(conn: sqlite3.Connection, run_id: str | None) -> dict:
    control = conn.execute("SELECT state, reason FROM control WHERE id = 1").fetchone()
    anomalies = [
        {"id": row[0], "cycle": row[1], "kind": _code(row[2]), "at": row[3]}
        for row in conn.execute(
            "SELECT e.id, e.cycle_id, e.kind, e.created_at FROM events e"
            " JOIN cycles c ON c.id = e.cycle_id"
            " WHERE c.run_id = ? AND e.severity = 'anomaly' ORDER BY e.id DESC LIMIT ?",
            (run_id, RECENT_ANOMALIES),
        )
    ]
    usage = [
        {
            "role": _code(row[0]),
            "calls": row[1],
            "input_tokens": row[2],
            "output_tokens": row[3],
            "headroom": row[4],
        }
        for row in conn.execute(
            "SELECT u.role, COUNT(*), SUM(u.input_tokens), SUM(u.output_tokens),"
            " (SELECT headroom FROM usage WHERE role = u.role AND headroom IS NOT NULL"
            "  ORDER BY id DESC LIMIT 1)"
            " FROM usage u JOIN cycles c ON c.id = u.cycle_id WHERE c.run_id = ?"
            " GROUP BY u.role ORDER BY u.role",
            (run_id,),
        )
    ]
    notes = [
        {"id": row[0], "text": row[1], "at": row[2]}
        for row in conn.execute(
            "SELECT id, text, created_at FROM memory_operator_notes ORDER BY id DESC"
        )
    ]
    return {
        "run": run_id,
        "runs": runs(conn),
        # The reason is "who: what" ("anomaly: plateau", "operator: pause"); both parts as codes.
        "control": {
            "state": control[0],
            "reason": [_code(part.strip()) for part in control[1].split(":", 1)],
        }
        if control
        else None,
        "anomalies": anomalies,
        "usage": usage,
        "notes": notes,
    }
