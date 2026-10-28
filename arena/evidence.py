"""A run, read back from the agent database as evidence a person can check.

`build` turns one run into a record per cycle. Every stored value carries the row it came from
(`table#id/column`, or `table#id/json/pointer` for a value inside a stored body), and every
computed value names its inputs, so anyone can check a number against the database. `write`
produces two halves:

- private/: the full story, attack texts and agent-written text included. It lives under runs/,
  which git ignores and the tracked-files guard refuses, and leaves the machine only through the
  case-study review (PLAN section 12a.7).
- public/: built from an allowlist of codes, counts and aggregate metrics only, and its report is
  written from those public records alone. No attack text and no agent or operator free text
  reaches it, because any of them can quote a working attack.

The database is opened read-only, so an export can run beside a live run and cannot change it.
Nothing here opens the Judge database, and the agent database never holds test numbers.
"""

import json
import re
import shutil
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pydantic

from arena import db
from arena.cycle import FINISHED
from arena.orchestrator import STEPS
from arena.schemas import DetectorConfig, JudgeReport
from arena.taxonomy import TECHNIQUES

# Backend names that called the real model. Any other name counts as simulated, so an unknown
# backend can never pass its numbers off as measurements.
LIVE_BACKENDS = frozenset({"live", "record"})
IN_PROGRESS = "in progress"
# What a committed cycle must leave behind. Add to it as later steps join the cycle.
REQUIRED_EPISODES = ("plan", "judge_report", "postmortem")
# Kept apart from memory.EPISODE_KINDS on purpose: a kind added there without being taught to this
# exporter shows up as "not shown" in the report instead of disappearing.
KNOWN_EPISODES = ("plan", "attack_batch", "patch", "judge_report", "postmortem", "novelty_closed")
# Events whose detail carries why a cycle was rolled back. The reason is free text: private only.
ROLLBACK_EVENTS = ("cycle_skipped", "cycle_abandoned")
# The cycle step that will patch the defence. Until it exists, a cycle's defence reads "not wired".
DEFENCE_STEP = "defend"
STANDING = {
    "baseline": "baseline",
    "candidate": "candidate",
    "not_kept": "not kept",
    "kept_provisional": "kept, provisional",
    "kept_reviewed": "kept, reviewed",
    "rejected": "rejected later",
}
METRICS = {"asr": "ASR", "utility": "Utility", "tpr_at_target_fpr": "TPR at target FPR"}
SNAPSHOT_TABLES = (
    "cycles",
    "manifests",
    "memory_episodic",
    "memory_lessons",
    "memory_predictions",
    "detector_configs",
    "events",
    "usage",
    "llm_calls",
)
# A run id printed in the public report must look like a code, not a sentence.
_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class EvidenceIncomplete(RuntimeError):
    """The run cannot be exported as it stands: a record is missing or does not match its schema."""


@dataclass(frozen=True)
class Pack:
    run_id: str
    simulated: bool
    # Highest row id per table at export, so a reader knows exactly what the pack covers.
    snapshot: dict[str, int]
    private: list[dict]
    public: list[dict]
    # Episode kinds this exporter does not know, counted so a new step cannot hide.
    unknown_kinds: dict[str, int]


def open_read_only(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise EvidenceIncomplete(f"There is no database at {path}.")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    except sqlite3.Error as error:
        conn.close()
        raise EvidenceIncomplete(f"{path} is not a readable arena database: {error}.") from error
    if version != db.SCHEMA_VERSION:
        conn.close()
        raise EvidenceIncomplete(
            f"The database is schema version {version}; this exporter reads {db.SCHEMA_VERSION}. "
            "Run any command that opens it normally to migrate it, then export again."
        )
    return conn


def _stored(value, table: str, row_id: int, *pointer) -> dict:
    return {"value": value, "from": "/".join([f"{table}#{row_id}", *map(str, pointer)])}


def _derived(name: str, value, *inputs: str) -> dict:
    return {"derived": name, "value": value, "inputs": list(inputs)}


def build(conn: sqlite3.Connection, run_id: str, cycles: range | None = None) -> Pack:
    """Read one run, or a range of its cycles, inside a single read transaction."""
    try:
        conn.execute("BEGIN")
        try:
            rows = conn.execute(
                "SELECT id, state FROM cycles WHERE run_id = ? ORDER BY id", (run_id,)
            ).fetchall()
            rows = [row for row in rows if cycles is None or row["id"] in cycles]
            if not rows:
                raise EvidenceIncomplete(f"Run {run_id!r} has no cycles to export.")
            private = [_read_cycle(conn, row["id"], row["state"]) for row in rows]
            snapshot = {
                table: conn.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]  # noqa: S608
                for table in SNAPSHOT_TABLES
            }
            ids = {row["id"] for row in rows}
            unknown = Counter(
                kind
                for cycle_id, kind in conn.execute(
                    "SELECT cycle_id, kind FROM memory_episodic"
                    " WHERE cycle_id IN (SELECT id FROM cycles WHERE run_id = ?)",
                    (run_id,),
                )
                if cycle_id in ids and kind not in KNOWN_EPISODES
            )
        finally:
            conn.execute("ROLLBACK")
    except sqlite3.Error as error:
        raise EvidenceIncomplete(f"The database could not be read: {error}.") from error
    simulated = any(record["backend"]["value"] == "simulated" for record in private)
    return Pack(run_id, simulated, snapshot, private, [_public(r) for r in private], dict(unknown))


def _read_cycle(conn: sqlite3.Connection, cycle_id: int, state: str) -> dict:
    try:
        return _cycle(conn, cycle_id, state)
    # ValueError covers pydantic's and json's errors; the others are a body in the wrong shape.
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise EvidenceIncomplete(
            f"In cycle {cycle_id}, a stored record is not in the shape this exporter expects:"
            f" {type(error).__name__} {error}."
        ) from error


def _cycle(conn: sqlite3.Connection, cycle_id: int, state: str) -> dict:
    committed = state == "committed"
    episodes = {
        kind: (row_id, json.loads(body))
        for row_id, kind, body in conn.execute(
            "SELECT id, kind, body FROM memory_episodic WHERE cycle_id = ? ORDER BY id", (cycle_id,)
        )
    }
    missing = [kind for kind in REQUIRED_EPISODES if committed and kind not in episodes]
    if missing:
        raise EvidenceIncomplete(f"Committed cycle {cycle_id} has no {', '.join(missing)} episode.")

    names = sorted(
        name
        for (name,) in conn.execute(
            "SELECT DISTINCT backend FROM llm_calls WHERE cycle_id = ?", (cycle_id,)
        )
    )
    judge_row = conn.execute(
        "SELECT id, judge_backend FROM manifests WHERE cycle_id = ?", (cycle_id,)
    ).fetchone()
    judge = judge_row["judge_backend"] if judge_row else None
    agents = "none" if not names else "live" if set(names) <= LIVE_BACKENDS else "simulated"
    # Live only when nothing in the cycle was simulated: the agents' calls and the Judge's models.
    # A manifest from before the Judge backend was recorded leaves the agents to decide.
    if "simulated" in (agents, judge):
        backend = "simulated"
    elif "live" in (agents, judge):
        backend = "live"
    else:
        backend = "none yet"
    judge_source = (
        f"manifests#{judge_row['id']}/judge_backend: {judge or 'not recorded'}"
        if judge_row
        else "no manifest"
    )
    plan = episodes.get("plan")
    events = conn.execute(
        "SELECT id, kind, detail FROM events WHERE cycle_id = ? ORDER BY id", (cycle_id,)
    ).fetchall()
    return {
        "cycle": _stored(cycle_id, "cycles", cycle_id, "id"),
        "state": (
            _stored(state, "cycles", cycle_id, "state")
            if state in FINISHED
            else _derived("unfinished_state", IN_PROGRESS, f"cycles#{cycle_id}/state")
        ),
        "backend": _derived(
            "live_only_if_every_call_was_live",
            backend,
            f"llm_calls.backend for cycle {cycle_id}: {', '.join(names) or 'none'}",
            judge_source,
        ),
        "manifest": _manifest(conn, cycle_id, committed),
        "plan": _plan(conn, cycle_id, plan),
        "attacks": _attacks(cycle_id, plan, episodes.get("attack_batch"), committed),
        "judge": _judge(cycle_id, episodes.get("judge_report")),
        "defence": _defence(conn, cycle_id),
        "postmortem": _postmortem(episodes.get("postmortem")),
        "lessons": [
            {
                "text": _stored(text, "memory_lessons", row_id, "text"),
                "status": _stored(status, "memory_lessons", row_id, "status"),
            }
            for row_id, text, status in conn.execute(
                "SELECT id, text, status FROM memory_lessons WHERE cycle_id = ? ORDER BY id",
                (cycle_id,),
            )
        ],
        "steps": [
            _stored(json.loads(detail)["outcome"], "events", row_id, "detail", "outcome")
            for row_id, kind, detail in events
            if kind == "step_done"
        ],
        "rollback_reasons": [
            _stored(json.loads(detail)["reason"], "events", row_id, "detail", "reason")
            for row_id, kind, detail in events
            if kind in ROLLBACK_EVENTS
        ],
        "event_kinds": _derived(
            "event_kind_counts",
            dict(Counter(kind for _, kind, _ in events if kind != "step_done")),
            f"events for cycle {cycle_id}",
        ),
        "tokens": _derived(
            "token_sum",
            conn.execute(
                "SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM usage"
                " WHERE cycle_id = ?",
                (cycle_id,),
            ).fetchone()[0],
            f"usage for cycle {cycle_id}",
        ),
    }


def _manifest(conn: sqlite3.Connection, cycle_id: int, committed: bool) -> dict | None:
    row = conn.execute("SELECT * FROM manifests WHERE cycle_id = ?", (cycle_id,)).fetchone()
    if row is None:
        if committed:
            raise EvidenceIncomplete(f"Committed cycle {cycle_id} has no manifest.")
        return None
    fields = ("seed", "config_hash", "git_sha", "constitution_hash", "judge_backend")
    manifest = {field: _stored(row[field], "manifests", row["id"], field) for field in fields}
    manifest["model_ids"] = {
        role: _stored(model, "manifests", row["id"], "model_ids", role)
        for role, model in json.loads(row["model_ids"]).items()
    }
    return manifest


def _plan(conn: sqlite3.Connection, cycle_id: int, plan: tuple[int, dict] | None) -> dict | None:
    if plan is None:
        return None
    row_id, body = plan
    actual = conn.execute(
        "SELECT id, actual_delta FROM memory_predictions WHERE cycle_id = ? ORDER BY id DESC",
        (cycle_id,),
    ).fetchone()
    return {
        "focus": _stored(body["focus"], "memory_episodic", row_id, "focus"),
        "hypothesis": _stored(
            body["hypothesis_text"], "memory_episodic", row_id, "hypothesis_text"
        ),
        "agents_to_run": _stored(body["agents_to_run"], "memory_episodic", row_id, "agents_to_run"),
        "expected_delta": _stored(
            body["prediction"]["expected_delta"],
            "memory_episodic",
            row_id,
            "prediction",
            "expected_delta",
        ),
        "confidence": _stored(
            body["prediction"]["confidence"], "memory_episodic", row_id, "prediction", "confidence"
        ),
        "actual_delta": (
            _stored(actual["actual_delta"], "memory_predictions", actual["id"], "actual_delta")
            if actual is not None and actual["actual_delta"] is not None
            else "not recorded yet"
        ),
    }


def _technique(name: str) -> str:
    """A technique name as the taxonomy knows it, or "other". The CEO's focus is an agent's choice,
    and nothing yet checks it against the shortlist, so it may only be shown as a known code."""
    return name if name in TECHNIQUES else "other"


def _attacks(
    cycle_id: int, plan: tuple[int, dict] | None, batch: tuple[int, dict] | None, committed: bool
) -> dict | str:
    if plan is not None and "attacker" not in plan[1]["agents_to_run"]:
        return "not run"
    if batch is None:
        if committed:
            raise EvidenceIncomplete(
                f"Committed cycle {cycle_id} ran the Attacker but has no attack_batch episode."
            )
        return "not reached"
    row_id, body = batch
    verdicts, bands = body["verdicts"], body["bands"]
    source = f"memory_episodic#{row_id}/verdicts"
    valid = [verdict for verdict in verdicts if verdict["valid"]]
    candidates = [
        index
        for index, verdict in enumerate(verdicts)
        if verdict["valid"] and not verdict["classified"] and bands[index] == "high"
    ]
    summary = {
        "tried": _derived("count", len(verdicts), source),
        "valid": _derived("count_valid", len(valid), source),
        "evaded": _derived("count_valid_and_evaded", sum(v["evaded"] for v in valid), source),
        "refused": _derived("count_refused", sum(v["refused"] for v in verdicts), source),
        "held_back": _derived("count_held_back", sum(v["held_back"] for v in verdicts), source),
        # Valid, matched by no known technique, and unlike anything in train or the archive.
        "new_technique_candidates": _derived(
            "count_valid_unclassified_high_novelty",
            len(candidates),
            source,
            f"memory_episodic#{row_id}/bands",
        ),
        "by_technique": _derived(
            "valid_by_technique", dict(Counter(_technique(v["technique"]) for v in valid)), source
        ),
        "by_behaviour": _derived(
            "valid_by_behaviour", dict(Counter(v["behaviour"] for v in valid)), source
        ),
        "novelty_bands": _derived(
            "band_counts", dict(Counter(bands)), f"memory_episodic#{row_id}/bands"
        ),
    }
    items = [
        {
            "text": _stored(text, "memory_episodic", row_id, "texts", index),
            "verdict": _stored(verdicts[index], "memory_episodic", row_id, "verdicts", index),
            "band": _stored(bands[index], "memory_episodic", row_id, "bands", index),
        }
        for index, text in enumerate(body["texts"])
    ]
    return {"summary": summary, "items": items}


def _judge(cycle_id: int, report: tuple[int, dict] | None) -> dict | None:
    if report is None:
        return None
    row_id, body = report
    try:
        # Extra fields are forbidden, so a field that could carry test numbers fails here, loudly.
        JudgeReport.model_validate(body)
    except pydantic.ValidationError as error:
        raise EvidenceIncomplete(
            f"In cycle {cycle_id}, the judge_report episode does not match the JudgeReport schema:"
            f" {error.errors()[0]['msg']}."
        ) from error
    return {
        field: _stored(value, "memory_episodic", row_id, field) for field, value in body.items()
    }


def _defence(conn: sqlite3.Connection, cycle_id: int) -> list[dict] | str:
    rows = conn.execute(
        "SELECT d.id, d.parent_id, d.status, d.config, p.config AS parent_config"
        " FROM detector_configs d LEFT JOIN detector_configs p ON p.id = d.parent_id"
        " WHERE d.cycle_id = ? ORDER BY d.id",
        (cycle_id,),
    ).fetchall()
    if not rows:
        return "no change" if DEFENCE_STEP in STEPS else "not wired"
    changes = []
    for row in rows:
        after = DetectorConfig.model_validate_json(row["config"]).model_dump(mode="json")
        source = f"detector_configs#{row['id']}/config"
        # The baseline has no parent, so nothing about it is a change.
        before, inputs = after, [source]
        if row["parent_config"]:
            before = DetectorConfig.model_validate_json(row["parent_config"]).model_dump(
                mode="json"
            )
            inputs.append(f"detector_configs#{row['parent_id']}/config")
        changed = sorted(field for field in after if before[field] != after[field])
        changes.append(
            {
                "config": _stored(row["id"], "detector_configs", row["id"], "id"),
                "parent": _stored(row["parent_id"], "detector_configs", row["id"], "parent_id"),
                "status": _stored(row["status"], "detector_configs", row["id"], "status"),
                # Statuses are as at export: a later review can still keep or reject the lineage.
                "standing": STANDING[row["status"]],
                "changed_fields": _derived("fields_differing_from_parent", changed, *inputs),
                "rule_count": _derived("count_rules", len(after["rules"]), source),
                "diff": _derived(
                    "parent_and_new_values",
                    {field: {"before": before[field], "after": after[field]} for field in changed},
                    *inputs,
                ),
            }
        )
    return changes


def _postmortem(postmortem: tuple[int, dict] | None) -> dict | None:
    if postmortem is None:
        return None
    row_id, body = postmortem
    fields = ("what_happened", "best_explanation", "what_would_change_it")
    return {field: _stored(body[field], "memory_episodic", row_id, field) for field in fields}


def _public(record: dict) -> dict:
    """The allowlist. Every key here holds a code, a count or an aggregate metric. Anything that
    can hold free text (hypotheses, post-mortems, lessons, step outcomes, rollback reasons, attack
    and rule text) stays out, and the focus is shown only as a known technique code."""
    plan, attacks, defence = record["plan"], record["attacks"], record["defence"]
    public_plan = None
    if plan:
        focus = plan["focus"]
        public_plan = {
            key: plan[key]
            for key in ("agents_to_run", "expected_delta", "confidence", "actual_delta")
        }
        public_plan["focus"] = (
            focus
            if _technique(focus["value"]) == focus["value"]
            else _derived("focus_not_a_known_technique", "other", focus["from"])
        )
    public_defence = defence
    if not isinstance(defence, str):
        keys = ("config", "parent", "status", "standing", "changed_fields", "rule_count")
        public_defence = [{key: change[key] for key in keys} for change in defence]
    return {
        "cycle": record["cycle"],
        "state": record["state"],
        "backend": record["backend"],
        "manifest": record["manifest"],
        "plan": public_plan,
        "attacks": attacks if isinstance(attacks, str) else attacks["summary"],
        "judge": record["judge"],
        "defence": public_defence,
        "lessons": _derived(
            "lesson_count",
            len(record["lessons"]),
            *(lesson["text"]["from"] for lesson in record["lessons"]),
        ),
        "event_kinds": record["event_kinds"],
        "tokens": record["tokens"],
    }


def chart_points(pack: Pack, metric: str) -> list[tuple[int, float, float, float]]:
    """(cycle, value, low, high) for committed cycles that measured the metric."""
    points = []
    for record in pack.public:
        judge = record["judge"]
        measured = judge and judge[metric]["value"]
        if record["state"]["value"] == "committed" and measured:
            points.append(
                (
                    record["cycle"]["value"],
                    measured["value"],
                    measured["ci_low"],
                    measured["ci_high"],
                )
            )
    return points


def _line_svg(points: list[tuple[int, float, float, float]], title: str) -> str:
    """A line with its confidence band, on a 0 to 1 scale, as plain SVG with no dependency."""
    width, height, pad = 480, 180, 30
    first, last = points[0][0], points[-1][0]

    def x(cycle: int) -> float:
        return pad + (cycle - first) / max(last - first, 1) * (width - 2 * pad)

    def y(value: float) -> float:
        return height - pad - min(max(value, 0.0), 1.0) * (height - 2 * pad)

    upper = " ".join(f"{x(c):.1f},{y(high):.1f}" for c, _, _, high in points)
    lower = " ".join(f"{x(c):.1f},{y(low):.1f}" for c, _, low, _ in reversed(points))
    line = " ".join(f"{x(c):.1f},{y(value):.1f}" for c, value, _, _ in points)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"'
        f' font-family="sans-serif" font-size="11">'
        f'<text x="{pad}" y="16">{title} by cycle (band: confidence interval)</text>'
        f'<line x1="{pad}" y1="{y(0)}" x2="{width - pad}" y2="{y(0)}" stroke="#999"/>'
        f'<text x="4" y="{y(0) + 4}">0</text><text x="4" y="{y(1) + 4}">1</text>'
        f'<polygon points="{upper} {lower}" fill="#9cc3e6" opacity="0.5"/>'
        f'<polyline points="{line}" fill="none" stroke="#1f5f99" stroke-width="2"/>'
        f'<text x="{pad}" y="{height - 8}">cycle {first}</text>'
        f'<text x="{width - pad - 50}" y="{height - 8}">cycle {last}</text>'
        "</svg>"
    )


def write(pack: Pack, out: Path) -> None:
    """Write both halves, replacing an earlier export in the same place so no stale file stays.

    A folder is only replaced if it is an earlier export (it holds `cycles.jsonl`), and both are
    checked before either is touched, so a careless `--out` cannot delete someone's own folder.
    """
    for half in ("private", "public"):
        folder = out / half
        if folder.exists() and not (folder / "cycles.jsonl").is_file():
            raise EvidenceIncomplete(
                f"{folder} exists and is not an earlier evidence export, so nothing was written."
                " Choose another --out."
            )
    for half in ("private", "public"):
        folder = out / half
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
        records = pack.private if half == "private" else pack.public
        lines = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
        (folder / "cycles.jsonl").write_text(lines)
        charts = []
        for metric, title in METRICS.items():
            points = chart_points(pack, metric)
            if points:
                (folder / f"{metric}.svg").write_text(_line_svg(points, title))
                charts.append((metric, title))
        (folder / "report.md").write_text(_report(pack, half, charts))


def _value(node):
    return node["value"] if isinstance(node, dict) and "value" in node else node


def _metric(judge: dict | None, metric: str) -> str:
    measured = judge and judge[metric]["value"]
    if not measured:
        return "not measured"
    return f"{measured['value']:.2f} ({measured['ci_low']:.2f} to {measured['ci_high']:.2f})"


def _report(pack: Pack, half: str, charts: list[tuple[str, str]]) -> str:
    """The public report reads only public records; the private one adds the agents' own words."""
    private = half == "private"
    states = Counter(record["state"]["value"] for record in pack.public)
    run_name = pack.run_id if private or _CODE.match(pack.run_id) else "(unnamed)"
    lines = [f"# Evidence: run {run_name} ({half})", ""]
    if pack.simulated:
        lines += [
            "> **Simulated.** At least one cycle used mock, replayed or simulated models, so these",
            "> numbers test the machinery. They are not measurements.",
            "",
        ]
    if not private:
        lines += [
            "Codes, counts and aggregate metrics only. Attack text and agent-written text are in",
            "the private half, which is never published as it stands.",
            "",
        ]
    lines += [
        f"{len(pack.public)} cycles: {states['committed']} committed, "
        f"{states['rolled_back']} rolled back, {states[IN_PROGRESS]} in progress. "
        "Statuses are as at export.",
        "",
        "Database snapshot (highest row id per table): "
        + ", ".join(f"{table} {top}" for table, top in pack.snapshot.items())
        + ".",
        "",
    ]
    manifest = next((record["manifest"] for record in pack.public if record["manifest"]), None)
    if manifest:
        models = ", ".join(
            f"{role} {_value(model)}" for role, model in manifest["model_ids"].items()
        )
        lines += [
            f"Seed {_value(manifest['seed'])}, config `{_value(manifest['config_hash'])[:12]}`, "
            f"commit `{_value(manifest['git_sha'])[:12]}`. Models: {models}.",
            "",
        ]
    lines += ["## Cycle by cycle", ""]
    for public, full in zip(pack.public, pack.private, strict=True):
        lines.append(f"- {_cycle_line(public, full if private else None)}")
    lines += [
        "",
        "## Measurements",
        "",
        "| Cycle | State | ASR | Utility | TPR at target FPR | Achieved FPR | Decision | Reason |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for record in pack.public:
        judge = record["judge"]
        fpr = judge and _value(judge["achieved_fpr"])
        decision = _value(judge["decision"]) if judge else "none"
        reason = _value(judge["reason_code"]) if judge else "none"
        lines.append(
            f"| {record['cycle']['value']} | {record['state']['value']} | "
            + " | ".join(_metric(judge, metric) for metric in METRICS)
            + f" | {'not measured' if fpr is None else f'{fpr:.3f}'} | {decision} | {reason} |"
        )
    if charts:
        lines += ["", "## Charts", "", "Committed cycles only."]
        lines += ["", *(f"![{title}]({metric}.svg)" for metric, title in charts)]
    if pack.unknown_kinds:
        lines += ["", "## Not shown", ""]
        lines += [
            f"- {count} records of kind `{kind}`" for kind, count in pack.unknown_kinds.items()
        ]
    return "\n".join(lines) + "\n"


def _cycle_line(record: dict, full: dict | None) -> str:
    """One cycle in a sentence or two, from a public record. `full` is the private record, given
    only for the private report, and adds the hypothesis, post-mortem and rollback reasons."""
    plan, attacks, judge = record["plan"], record["attacks"], record["judge"]
    state, backend = record["state"]["value"], record["backend"]["value"]
    parts = [f"**Cycle {record['cycle']['value']}**, {state}, {backend}."]
    if plan:
        parts.append(f"Focus `{_value(plan['focus'])}`.")
        if full:
            parts.append(f"Hypothesis: {_value(full['plan']['hypothesis'])}")
        parts.append(
            f"Predicted change {_value(plan['expected_delta']):+.2f} "
            f"(confidence {_value(plan['confidence']):.2f}); "
            f"actual {_value(plan['actual_delta'])}."
        )
    if isinstance(attacks, str):
        parts.append(f"Attacks: {attacks}.")
    else:
        parts.append(
            f"Attacks: {_value(attacks['tried'])} tried, {_value(attacks['valid'])} valid, "
            f"{_value(attacks['evaded'])} evaded, "
            f"{_value(attacks['new_technique_candidates'])} new-technique candidates."
        )
    if judge:
        parts.append(
            f"Judge: ASR {_metric(judge, 'asr')}; decision {_value(judge['decision'])}, "
            f"reason {_value(judge['reason_code'])}."
        )
    defence = record["defence"]
    if isinstance(defence, str):
        parts.append(f"Defence: {defence}.")
    else:
        parts.append(
            "Defence: "
            + "; ".join(
                f"config {change['config']['value']} {change['standing']}"
                + (
                    ", the starting point"
                    if change["parent"]["value"] is None
                    else f", changed {', '.join(_value(change['changed_fields'])) or 'nothing'}"
                )
                for change in defence
            )
            + "."
        )
    parts.append(f"Lessons added: {_value(record['lessons'])}.")
    if full and full["postmortem"]:
        parts.append(f"Post-mortem: {_value(full['postmortem']['what_happened'])}")
    if full and full["rollback_reasons"]:
        reasons = "; ".join(_value(reason) for reason in full["rollback_reasons"])
        parts.append(f"Rolled back because: {reasons}.")
    kinds = _value(record["event_kinds"])
    if kinds:
        parts.append(
            "Events: " + ", ".join(f"{kind} x{count}" for kind, count in kinds.items()) + "."
        )
    return " ".join(parts)
