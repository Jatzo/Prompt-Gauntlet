"""What the dashboard's arena view draws for each finished cycle: codes, flags and counts only.

The arena shows each attack of a cycle's batch as a dot that is refused, has no effect, is caught by
the incumbent detector or gets past it; then the Defender's patch and the Judge's decision. This
module reads only the fields that picture needs, from a read-only connection the caller opens:

- the plan's focus, through `evidence.technique_code`, so an agent's free text is never shown;
- the batch's verdicts, never its texts: technique code, valid, evaded, held back, refused;
- the patch's op kinds and the fields they touch, never its patterns, values or rationale;
- the Judge's decision, reason code and aggregate ASR and TPR;
- the rule counts of the config patched and of the incumbent after the cycle;
- whether the cycle ran live or simulated, through `evidence.backend_of`.

A valid attack is one that acted on the undefended target; evaded means the incumbent missed it. The
Judge records evasion for valid attacks only, so an invalid attack is drawn as having no effect,
whatever the detector did. A cycle that cannot be read comes back marked unreadable, so one bad
cycle never hides the others.
"""

import json
import sqlite3

from arena.cycle import FINISHED
from arena.evidence import backend_of, technique_code

PAGE = 50
_ROLES = frozenset({"attacker", "defender", "researcher"})
_OPS = frozenset({"add", "remove", "replace"})
_FIELDS = frozenset({"rules", "normalisers", "classifier_prompt", "layers"})
_STANDING = ("baseline", "kept_provisional", "kept_reviewed")


def cycles_after(conn: sqlite3.Connection, after: int, run_id: str | None = None) -> dict:
    """Up to `PAGE` finished cycles with ids above `after`, oldest first, and where to ask next.
    With `run_id`, only that run's cycles.

    `next_after` never passes a cycle that is still open, so a cycle finishing later is still
    fetched; the page drops any cycle it already holds.
    """
    placeholders = ",".join("?" * len(FINISHED))
    scope, scope_args = (" AND run_id = ?", (run_id,)) if run_id is not None else ("", ())
    rows = conn.execute(
        f"SELECT id, run_id, state FROM cycles WHERE id > ? AND state IN ({placeholders})"  # noqa: S608
        f"{scope} ORDER BY id LIMIT ?",
        (after, *FINISHED, *scope_args, PAGE),
    ).fetchall()
    open_row = conn.execute(
        f"SELECT MIN(id) FROM cycles WHERE id > ? AND state NOT IN ({placeholders}){scope}",  # noqa: S608
        (after, *FINISHED, *scope_args),
    ).fetchone()
    next_after = rows[-1]["id"] if rows else after
    if open_row[0] is not None:
        next_after = min(next_after, open_row[0] - 1)
    cycles = []
    for row in rows:
        try:
            cycles.append(_cycle(conn, row["id"], row["run_id"], row["state"]))
        # A stored body in an unexpected shape; the rest of the page still loads.
        except (KeyError, TypeError, ValueError, AttributeError):
            cycles.append({"cycle": row["id"], "unreadable": True})
    return {"cycles": cycles, "next_after": max(next_after, after)}


def _episode(conn: sqlite3.Connection, cycle_id: int, kind: str) -> dict | None:
    row = conn.execute(
        "SELECT body FROM memory_episodic WHERE cycle_id = ? AND kind = ? ORDER BY id DESC LIMIT 1",
        (cycle_id, kind),
    ).fetchone()
    return json.loads(row["body"]) if row else None


def _cycle(conn: sqlite3.Connection, cycle_id: int, run_id: str, state: str) -> dict:
    plan = _episode(conn, cycle_id, "plan")
    batch = _episode(conn, cycle_id, "attack_batch")
    patch = _episode(conn, cycle_id, "patch")
    report = _episode(conn, cycle_id, "judge_report")
    return {
        "cycle": cycle_id,
        "state": state,
        "backend": backend_of(conn, cycle_id)[0],
        "focus": technique_code(plan["focus"]) if plan else None,
        "agents": sorted(role for role in (plan or {}).get("agents_to_run", ()) if role in _ROLES),
        "attacks": [_attack(verdict) for verdict in batch["verdicts"]] if batch else [],
        "patch": _patch(patch),
        "judge": _judge(report),
        "rules": _rules(conn, cycle_id, run_id),
    }


def _attack(verdict: dict) -> dict:
    return {
        "technique": technique_code(verdict["technique"]),
        "valid": verdict["valid"] is True,
        "evaded": verdict["evaded"] is True,
        "held_back": verdict["held_back"] is True,
        "refused": verdict["refused"] is True,
    }


def _patch(patch: dict | None) -> dict | None:
    if patch is None:
        return None
    ops = []
    for op in patch["patch"]["ops"]:
        field = op["path"].strip("/").split("/")[0]
        ops.append(
            {
                "op": op["op"] if op["op"] in _OPS else "other",
                "field": field if field in _FIELDS else "other",
            }
        )
    return {"ops": ops, "refused": "refused" in patch}


def _metric(value: object) -> float | None:
    if isinstance(value, dict) and isinstance(value.get("value"), int | float):
        return float(value["value"])
    return None


def _judge(report: dict | None) -> dict | None:
    if report is None:
        return None
    decision = report["decision"]
    reason = report["reason_code"]
    return {
        "decision": decision if decision in ("keep", "reject", "none") else "none",
        "reason": reason if isinstance(reason, str) and reason.isidentifier() else "other",
        "asr": _metric(report.get("asr")),
        "tpr": _metric(report.get("tpr_at_target_fpr")),
    }


def _rule_count(config: str) -> int:
    return len(json.loads(config)["rules"])


def _rules(conn: sqlite3.Connection, cycle_id: int, run_id: str) -> dict:
    """The rule count of the config the cycle patched, and of the run's incumbent after it."""
    placeholders = ",".join("?" * len(_STANDING))
    standing = conn.execute(
        f"SELECT d.config FROM detector_configs d JOIN cycles c ON c.id = d.cycle_id"  # noqa: S608
        f" WHERE c.run_id = ? AND d.cycle_id <= ? AND d.status IN ({placeholders})"
        " ORDER BY d.id DESC LIMIT 1",
        (run_id, cycle_id, *_STANDING),
    ).fetchone()
    candidate = conn.execute(
        "SELECT p.config FROM detector_configs d JOIN detector_configs p ON p.id = d.parent_id"
        " WHERE d.cycle_id = ? ORDER BY d.id DESC LIMIT 1",
        (cycle_id,),
    ).fetchone()
    after = _rule_count(standing["config"]) if standing else None
    before = _rule_count(candidate["config"]) if candidate else after
    return {"before": before, "after": after}
