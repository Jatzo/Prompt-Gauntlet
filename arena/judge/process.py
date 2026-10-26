"""The Judge process: JSON lines over stdin and stdout, and no network port.

Requests are `{"id": n, "method": ..., "params": {...}}`. Each gets one reply line,
`{"id": n, "ok": true, "result": ...}` or `{"id": n, "ok": false, "error": "..."}`.

Methods:
- ping: liveness.
- verify_hashes: the constitution and the frozen test set against their committed pins.
- evaluate: a JudgeReport of aggregates. Phase 1 returns a stub marked not_implemented.
- measure: a BaselineReport of aggregates for every requested arm and target.
"""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from arena.judge import measure, store
from arena.judge.data import verify_test_set
from arena.judge.hashing import read_pin, sha256_text
from arena.schemas import JudgeReport, MeasureRequest


def judge_dir() -> Path:
    default = Path.home() / ".prompt-gauntlet" / "judge"
    return Path(os.environ.get("ARENA_JUDGE_DIR", default))


def verify_hashes(root: Path, data_dir: Path) -> dict:
    constitution = root / "constitution.md"
    constitution_pin = root / "constitution.sha256"
    actual = sha256_text(constitution) if constitution.exists() else None
    expected = read_pin(constitution_pin) if constitution_pin.exists() else None
    constitution_status = "ok" if actual is not None and actual == expected else "mismatch"

    test_status = verify_test_set(root, data_dir)

    return {
        "ok": constitution_status == "ok" and test_status in ("ok", "placeholder"),
        "constitution": constitution_status,
        "constitution_hash": actual,
        "test_set": test_status,
    }


def evaluate(conn, params: dict) -> dict:
    report = JudgeReport(
        asr=None,
        utility=None,
        tpr_at_target_fpr=None,
        achieved_fpr=None,
        per_category_fpr={},
        regression_status="not_run",
        decision="none",
        reason_code="not_implemented",
    ).model_dump(mode="json")
    conn.execute(
        "INSERT INTO evaluations (cycle_id, report, created_at) VALUES (?, ?, ?)",
        (int(params["cycle_id"]), json.dumps(report), datetime.now(UTC).isoformat()),
    )
    return report


def handle(request: dict, root: Path, data_dir: Path, conn) -> dict:
    method = request.get("method")
    params = request.get("params") or {}
    if method == "ping":
        return {"pong": True}
    if method == "verify_hashes":
        return verify_hashes(root, data_dir)
    if method == "evaluate":
        return evaluate(conn, params)
    if method == "measure":
        context = measure.Context(root, data_dir, store.EvalCache(conn))
        return measure.run(MeasureRequest.model_validate(params), context).model_dump(mode="json")
    raise ValueError(f"unknown method {method!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m arena.judge")
    parser.add_argument("--root", type=Path, required=True, help="repository root")
    args = parser.parse_args(argv)
    data_dir = judge_dir()
    conn = store.connect(data_dir / "judge.db")

    for line in sys.stdin:
        if not line.strip():
            continue
        request_id = None
        try:
            request = json.loads(line)
            request_id = request.get("id")
            reply = {
                "id": request_id,
                "ok": True,
                "result": handle(request, args.root, data_dir, conn),
            }
        except Exception as error:  # noqa: BLE001  one bad request must not kill the Judge
            reply = {"id": request_id, "ok": False, "error": f"{type(error).__name__}: {error}"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    conn.close()
    return 0
