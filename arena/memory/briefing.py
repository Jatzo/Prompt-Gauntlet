"""The CEO's briefing: assembled by code from the database each cycle (PLAN section 9).

The CEO never reads raw history. This module reads the run's memory and writes one bounded text in
PLAN's order: operator notes, current dev scores (no test numbers), lessons relevant to the
shortlist, the open backlog, recent experiments, calibration (once enough pairs exist), open
findings, anomalies and open operator questions. The constitution is the first part of every
agent's system prompt, so it is counted against the budget but not repeated here.

Each section has a share of `briefing_token_budget`. A section over its share drops its weakest
items first: lessons by relevance, then confidence; the backlog and experiments oldest first.
Operator notes are never dropped. Everything an agent wrote (lessons, backlog items, hypotheses)
arrives datamarked as quoted data, since it may carry text from an attack.

The no-memory ablation arm gets the operator notes and dev scores only (PLAN section 14.2).
"""

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from arena.config import ArenaConfig
from arena.datamark import quote
from arena.memory import calibration
from arena.memory.lessons import actual_delta
from arena.schemas import JudgeReport

CHARS_PER_TOKEN = 4
# Shares of the budget left after the constitution and the operator notes, which are never cut.
SHARES = {"scores": 0.08, "lessons": 0.32, "backlog": 0.15, "experiments": 0.3, "calibration": 0.05}
RECENT_ANOMALIES = 5


@dataclass(frozen=True)
class Briefing:
    text: str
    # Lessons shown, for the briefing-usage check: a plan may cite only these.
    lesson_ids: tuple[int, ...]
    # Operator notes the next post-mortem must acknowledge.
    new_note_ids: tuple[int, ...]
    dropped: dict[str, int] = field(default_factory=dict)


def build(
    conn: sqlite3.Connection,
    run_id: str,
    *,
    config: ArenaConfig,
    root: Path,
    foci: tuple[str, ...] = (),
    use_memory: bool = True,
) -> Briefing:
    constitution = (root / "constitution.md").read_text()
    budget = config.briefing_token_budget * CHARS_PER_TOKEN - len(constitution)
    dropped: dict[str, int] = {}

    notes, new_ids = _notes(conn, run_id, config)
    budget -= len(notes)
    parts = [notes, _fit("scores", [_scores(conn, run_id, config)], budget, dropped)]
    lesson_ids: tuple[int, ...] = ()
    if use_memory:
        lessons = _lessons(conn, run_id, foci, config)
        kept = _fit_items("lessons", lessons, budget, dropped)
        lesson_ids = tuple(lesson_id for lesson_id, _ in kept)
        parts.append(_section("Lessons relevant to the shortlist", [text for _, text in kept]))
        parts.append(
            _section(
                "Open backlog",
                _fit_items(
                    "backlog", _backlog(conn, run_id, config), budget, dropped, keep_ids=False
                ),
            )
        )
        parts.append(
            _section(
                "Recent experiments",
                _fit_items(
                    "experiments",
                    _experiments(conn, run_id, config),
                    budget,
                    dropped,
                    keep_ids=False,
                ),
            )
        )
        summary = calibration.summary(calibration.pairs(conn, run_id), config)
        if summary:
            parts.append(
                _fit(
                    "calibration", [_section("Your prediction record", [summary])], budget, dropped
                )
            )
    parts.append(_section("Open findings", ["None yet."]))
    parts.append(_section("Recent anomalies", _anomalies(conn, run_id)))
    parts.append(_section("Open operator questions", ["None."]))
    text = "\n\n".join(part for part in parts if part)
    return Briefing(text, lesson_ids, new_ids, dropped)


def _section(title: str, lines: list[str]) -> str:
    body = "\n".join(lines) if lines else "None."
    return f"## {title}\n{body}"


def _fit(name: str, texts: list[str], budget: int, dropped: dict[str, int]) -> str:
    share = int(max(budget, 0) * SHARES[name])
    text = "\n".join(texts)
    if len(text) <= share:
        return text
    dropped[name] = 1
    return text[:share]


def _fit_items(name, items, budget, dropped, *, keep_ids=True):
    """Items arrive strongest first; keep as many as the section's share allows."""
    share = int(max(budget, 0) * SHARES[name])
    kept, used = [], 0
    for item in items:
        size = len(item[1] if keep_ids else item)
        if used + size > share:
            break
        kept.append(item)
        used += size
    if len(kept) < len(items):
        dropped[name] = len(items) - len(kept)
    return kept


def _in_run(table: str) -> str:
    return f"{table} t JOIN cycles c ON c.id = t.cycle_id WHERE c.run_id = ?"


def unacknowledged_notes(conn: sqlite3.Connection, run_id: str) -> tuple[int, ...]:
    """Operator notes no committed post-mortem of this run has acknowledged; the next one must."""
    acknowledged: set[int] = set()
    for (body,) in conn.execute(
        "SELECT t.body FROM memory_episodic t JOIN cycles c ON c.id = t.cycle_id"
        " WHERE c.run_id = ? AND c.state = 'committed' AND t.kind = 'postmortem'",
        (run_id,),
    ):
        acknowledged.update(json.loads(body).get("operator_notes_acknowledged", []))
    ids = conn.execute("SELECT id FROM memory_operator_notes ORDER BY id").fetchall()
    return tuple(row[0] for row in ids if row[0] not in acknowledged)


def _notes(
    conn: sqlite3.Connection, run_id: str, config: ArenaConfig
) -> tuple[str, tuple[int, ...]]:
    """Every operator note, newest first, the unacknowledged ones marked new."""
    rows = conn.execute("SELECT id, text FROM memory_operator_notes ORDER BY id DESC").fetchall()
    new_ids = unacknowledged_notes(conn, run_id)
    new = " (new: acknowledge it in your post-mortem)"
    lines = [
        f"- Note {row[0]}{new if row[0] in new_ids else ''}:\n{quote(row[1], config.seed)}"
        for row in rows
    ]
    title = "Operator notes (highest priority, newest first)"
    return (_section(title, lines) if lines else ""), new_ids


def _scores(conn: sqlite3.Connection, run_id: str, config: ArenaConfig) -> str:
    """The Judge's latest dev measurement in this run: aggregates only, never test numbers."""
    row = conn.execute(
        "SELECT t.cycle_id, t.body FROM memory_episodic t JOIN cycles c ON c.id = t.cycle_id"
        " WHERE c.run_id = ? AND c.state = 'committed' AND t.kind = 'judge_report'"
        " AND json_extract(t.body, '$.asr') IS NOT NULL ORDER BY t.id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    if row is None:
        return _section("Current dev scores", ["No measurement yet."])
    report = JudgeReport.model_validate_json(row[1])
    verdict = {"keep": "kept", "reject": "rejected"}.get(report.decision)
    outcome = f"the Judge {verdict} the candidate" if verdict else "there was no candidate"
    lines = [f"Measured in cycle {row[0]}; {outcome} ({report.reason_code})."]
    delta = actual_delta(report, config)
    if delta is not None:
        incumbent = report.asr.value - delta
        lines.append(f"Incumbent end-to-end ASR {incumbent:.3f}.")
    for name, metric in (
        ("Candidate end-to-end ASR", report.asr),
        ("Candidate utility", report.utility),
        ("Candidate TPR at the target FPR", report.tpr_at_target_fpr),
    ):
        if metric is not None:
            lines.append(
                f"{name} {metric.value:.3f} (CI {metric.ci_low:.3f} to {metric.ci_high:.3f},"
                f" {metric.clusters} clusters)."
            )
    return _section("Current dev scores (dev only, never test)", lines)


def _lessons(conn, run_id, foci, config) -> list[tuple[int, str]]:
    words = {word for focus in foci for word in focus.split(".")}
    rows = conn.execute(
        f"SELECT t.id, t.text, t.scope_tags, t.confidence FROM {_in_run('memory_lessons')}"  # noqa: S608
        " AND t.status = 'active'",
        (run_id,),
    ).fetchall()

    def strength(row) -> tuple[int, float, int]:
        relevance = len(words & set(json.loads(row[2])))
        return (relevance, row[3], row[0])

    ordered = sorted(rows, key=strength, reverse=True)
    return [
        (
            row[0],
            f"- Lesson {row[0]} (confidence {row[3]:.2f}, tags {', '.join(json.loads(row[2]))}):"
            f"\n{quote(row[1], config.seed)}",
        )
        for row in ordered
    ]


def _backlog(conn, run_id, config) -> list[str]:
    rows = conn.execute(
        f"SELECT t.id, t.text, t.status FROM {_in_run('memory_backlog')}"  # noqa: S608
        " AND t.status IN ('proposed', 'running') ORDER BY t.id DESC",
        (run_id,),
    ).fetchall()
    return [f"- Item {row[0]} ({row[2]}):\n{quote(row[1], config.seed)}" for row in rows]


def _experiments(conn, run_id, config) -> list[str]:
    cycles = conn.execute(
        "SELECT id FROM cycles WHERE run_id = ? AND state = 'committed' ORDER BY id DESC LIMIT ?",
        (run_id, config.briefing_recent_experiments),
    ).fetchall()
    lines = []
    for (cycle_id,) in cycles:
        bodies = {
            kind: json.loads(body)
            for kind, body in conn.execute(
                "SELECT kind, body FROM memory_episodic WHERE cycle_id = ?"
                " AND kind IN ('plan', 'judge_report')",
                (cycle_id,),
            )
        }
        plan, report = bodies.get("plan"), bodies.get("judge_report")
        if plan is None:
            continue
        prediction = conn.execute(
            "SELECT expected_delta, actual_delta FROM memory_predictions WHERE cycle_id = ?",
            (cycle_id,),
        ).fetchone()
        outcome = (
            "no outcome"
            if prediction is None or prediction[1] is None
            else f"actual {prediction[1]:+.3f}"
        )
        expected = "" if prediction is None else f"predicted {prediction[0]:+.3f}, {outcome}; "
        verdict = (
            f"Judge {report['decision']} ({report['reason_code']})" if report else "no Judge report"
        )
        lines.append(
            f"- Cycle {cycle_id}, focus {plan['focus']}: {expected}{verdict}."
            f" Hypothesis:\n{quote(plan['hypothesis_text'], config.seed)}"
        )
    return lines


def _anomalies(conn: sqlite3.Connection, run_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT e.cycle_id, e.kind FROM events e JOIN cycles c ON c.id = e.cycle_id"
        " WHERE c.run_id = ? AND e.severity = 'anomaly' ORDER BY e.id DESC LIMIT ?",
        (run_id, RECENT_ANOMALIES),
    ).fetchall()
    return [f"- Cycle {row[0]}: {row[1]}." for row in rows]
