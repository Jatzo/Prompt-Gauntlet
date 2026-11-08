"""Prints every figure in docs/arena.md from the live arena's private files, and checks public files
for its attack text before they are committed.

The arena database holds every agent output, the Attacker's queries and batches among them, and the
Judge copy holds each played attack, so both stay private. `report` prints counts, kinds and times
only. `check` is part 3's leak gate: the same 5-word-run test as `discovery_report.py check`, run
against every attack the Judge stored for the run and every raw Attacker output in the arena
database, a rerouted or invalid one included.

Usage, from the repo root:
  python scripts/arena_report.py report [RUN_ID]          (default a1)
  python scripts/arena_report.py check FILE [FILE ...]    (exit 1 on any match)
"""

import importlib.util
import json
import sqlite3
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARENA_DB = ROOT / "runs" / "arena-live.db"
JUDGE_DB = ROOT / "private" / "judge-arena" / "judge.db"
RUN_ID = "a1"

_spec = importlib.util.spec_from_file_location(
    "discovery_report", ROOT / "scripts" / "discovery_report.py"
)
discovery_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(discovery_report)


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def _cycles(arena: sqlite3.Connection, run_id: str) -> list[tuple]:
    return arena.execute(
        "SELECT id, state, created_at, updated_at FROM cycles WHERE run_id = ? ORDER BY id",
        (run_id,),
    ).fetchall()


def _texts(raw: str) -> list[tuple[str, str]]:
    """(text, the Attacker's own label) for each attack or query in one raw output. Output that is
    not the expected JSON, such as a rerouted reply, is checked whole."""
    try:
        body = json.loads(raw)
    except ValueError:
        return [(raw, "")]
    if isinstance(body, dict) and isinstance(body.get("text"), str):
        return [(body["text"], "")]
    if isinstance(body, dict) and isinstance(body.get("attacks"), list):
        return [
            (a, "") if isinstance(a, str) else (a.get("text", ""), a.get("technique", ""))
            for a in body["attacks"]
        ]
    return [(raw, "")]


def attack_rows(arena_db: Path, judge_db: Path, run_id: str) -> list[dict]:
    """Every attack text of the run, in the row shape `discovery_report.leaks` reads."""
    arena, judge = _connect(arena_db), _connect(judge_db)
    ids = [row[0] for row in _cycles(arena, run_id)]
    rows = []
    for cycle_id in ids:
        for step, raw in arena.execute(
            "SELECT step, raw_output FROM llm_calls WHERE cycle_id = ? AND role = 'attacker'",
            (cycle_id,),
        ):
            for index, (text, label) in enumerate(_texts(raw)):
                rows.append(_row(cycle_id, f"{step}/{index}", text, label))
        for idx, text in judge.execute(
            "SELECT idx, text FROM attacks WHERE cycle_id = ?", (cycle_id,)
        ):
            rows.append(_row(cycle_id, f"played/{idx}", text, ""))
    arena.close()
    judge.close()
    return rows


def _row(cycle_id: int, index: str, text: str, label: str) -> dict:
    return {"round": cycle_id, "index": index, "text": text, "claimed_technique": label}


def summary(arena_db: Path, judge_db: Path, run_id: str) -> dict:
    arena, judge = _connect(arena_db), _connect(judge_db)
    cycles = []
    for cycle_id, state, created, updated in _cycles(arena, run_id):
        start, end = datetime.fromisoformat(created), datetime.fromisoformat(updated)
        calls = Counter(
            (role, model, "ok" if valid else (failure or "invalid"))
            for role, model, valid, failure in arena.execute(
                "SELECT role, model_id, valid, failure FROM llm_calls WHERE cycle_id = ?",
                (cycle_id,),
            )
        )
        tokens = {
            role: (int(tin), int(tout))
            for role, tin, tout in arena.execute(
                "SELECT role, SUM(input_tokens), SUM(output_tokens) FROM usage"
                " WHERE cycle_id = ? GROUP BY role",
                (cycle_id,),
            )
        }
        events = [
            (kind, severity, json.loads(detail), at)
            for kind, severity, detail, at in arena.execute(
                "SELECT kind, severity, detail, created_at FROM events WHERE cycle_id = ?"
                " ORDER BY id",
                (cycle_id,),
            )
        ]
        played = judge.execute(
            "SELECT channel, valid, refused FROM attacks WHERE cycle_id = ?", (cycle_id,)
        ).fetchall()
        judge_calls = Counter(
            model
            for (model,) in judge.execute(
                "SELECT model_id FROM eval_cache WHERE created_at BETWEEN ? AND ?",
                (created, updated),
            )
        )
        cycles.append(
            {
                "cycle": cycle_id,
                "state": state,
                "start": created,
                "end": updated,
                "minutes": round((end - start).total_seconds() / 60, 1),
                "agent_calls": {" / ".join(key): n for key, n in sorted(calls.items())},
                "tokens_in_out": tokens,
                "steps": [
                    (e[2].get("step"), e[2].get("outcome"), e[3])
                    for e in events
                    if e[0] == "step_done"
                ],
                "anomalies": [
                    {
                        k: v
                        for k, v in e[2].items()
                        if k in ("message", "role", "expected", "reported")
                    }
                    | {"kind": e[0], "at": e[3]}
                    for e in events
                    if e[1] == "anomaly"
                ],
                "other_events": sorted(
                    {e[0] for e in events if e[1] == "info" and e[0] != "step_done"}
                ),
                "attacks_played": len(played),
                "attacks_valid": sum(v for _, v, _ in played),
                "channels": dict(Counter(c for c, _, _ in played)),
                "judge_cache_rows_by_model": dict(judge_calls),
            }
        )
    control = arena.execute("SELECT state, reason FROM control").fetchone()
    arena.close()
    judge.close()
    return {"run_id": run_id, "control": control, "cycles": cycles}


def main(argv: list[str], arena_db: Path = ARENA_DB, judge_db: Path = JUDGE_DB) -> int:
    if argv[:1] == ["check"] and len(argv) > 1:
        rows = attack_rows(arena_db, judge_db, RUN_ID)
        if not rows:
            print("No arena attack text found, so there is nothing to check against.")
            return 2
        dirty = 0
        for name in argv[1:]:
            found = discovery_report.leaks(rows, Path(name).read_text())
            dirty += len(found)
            print(f"{name}: {'clean' if not found else f'{len(found)} matches'}")
            for item in found[:20]:
                print("  ", item)
        return 1 if dirty else 0
    if argv[:1] == ["report"]:
        run_id = argv[1] if len(argv) > 1 else RUN_ID
        print(json.dumps(summary(arena_db, judge_db, run_id), indent=1, default=str))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
