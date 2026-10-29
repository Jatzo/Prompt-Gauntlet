"""The operator's dashboard: an SSE stream over the agent database's `events` table and JSON reads
for the four panels (PLAN section 15).

Reads are read-only by construction: the database is opened with a `mode=ro` URI through plain
`sqlite3`, never through `arena.db`, which creates, migrates and writes. Each event reaches the page
through an allowlist, so a later event that carries text, scores or sample ids cannot leak without
a change here. Bound to 127.0.0.1 only, with a host check against DNS rebinding.

The arena view reads `/arena/cycles`, which returns codes, flags and counts per finished cycle
through `arena_feed`, never text. The score, memory and operations panels read `/dashboard/*`
through `dashboard_feed`; only the memory panel carries agent text.

The only writes are the control flag and operator notes, through `operator_writes`. Each POST needs
the token this process made at start (the same-origin page fetches it from `/dashboard/token`) in
the `X-Arena-Token` header, a JSON body, and an Origin that matches the host. No CORS headers are
ever sent, so another origin can neither read the token nor send the header without a preflight
that fails. The page may not be framed. Review actions come with the review queue (step 13b).

The page lives in `arena/static/`, which the package build does not ship; it runs from the repo.
"""

import argparse
import hmac
import json
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from arena import dashboard_feed, operator_writes
from arena.arena_feed import cycles_after
from arena.config import agent_db_path
from arena.schemas import STEP_OUTCOME

HOST = "127.0.0.1"
PORT = 8765
STATIC = Path(__file__).parent / "static"
# The page's typefaces, served by exact name only, so no request can reach another file.
FONTS = frozenset(
    {
        "IBMPlexSans-Regular-Latin1.woff2",
        "IBMPlexSans-SemiBold-Latin1.woff2",
        "IBMPlexSans-Bold-Latin1.woff2",
        "IBMPlexMono-Regular-Latin1.woff2",
        "IBMPlexMono-SemiBold-Latin1.woff2",
    }
)
POLL_SECONDS = 1.0
KEEPALIVE_SECONDS = 15.0
# Rows per poll, so a first connect to a long run does not read the whole table at once.
BATCH = 500
# Anomaly rows carry the agent's own role and tool strings, so role, tool, step and kind must be
# identifiers, and anything else is dropped rather than shown. Outcomes are fixed phrases.
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; connect-src 'self'; script-src 'self'; font-src 'self';"
        " style-src 'unsafe-inline';"
        " frame-ancestors 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


def _safe(value: object, pattern: re.Pattern[str] = _IDENTIFIER) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def project(row: sqlite3.Row) -> dict:
    """The only fields of an event the page ever sees."""
    try:
        detail = json.loads(row["detail"])
    except (TypeError, ValueError):
        detail = {}
    if not isinstance(detail, dict):
        detail = {}
    kind = _safe(row["kind"]) or "event"
    return {
        "id": row["id"],
        "time": row["created_at"],
        "cycle": row["cycle_id"],
        "kind": kind,
        "severity": "anomaly" if row["severity"] == "anomaly" else "info",
        "role": _safe(detail.get("role")),
        "tool": _safe(detail.get("tool")),
        "step": _safe(detail.get("step")),
        # Outcomes are fixed-format only on step_done rows; elsewhere the key may hold free text.
        "outcome": _safe(detail.get("outcome"), STEP_OUTCOME) if kind == "step_done" else None,
    }


def open_read_only(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _status(state: str) -> str:
    return f"event: status\ndata: {json.dumps({'state': state})}\n\n"


def stream(
    path: Path,
    after: int,
    *,
    polls: int | None = None,
    poll_seconds: float = POLL_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Iterator[str]:
    """SSE messages for every event after `after`, polling by id. `polls` bounds the loop for tests.

    The database is reopened on every poll, so a run that replaces the file is picked up. Starlette
    stops pulling from this generator once it sees the client has gone, at the latest when the next
    keepalive fails to send.
    """
    last, state, quiet_since = after, None, clock()
    done = 0
    while polls is None or done < polls:
        done += 1
        reset = False
        try:
            conn = open_read_only(path)
            try:
                top = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
                if top < last:
                    # A new database replaced the old one, and its ids start again from 1.
                    last, reset = 0, True
                rows = conn.execute(
                    "SELECT id, cycle_id, kind, severity, detail, created_at FROM events"
                    " WHERE id > ? ORDER BY id LIMIT ?",
                    (last, BATCH),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.OperationalError:
            # No file yet, or a file with no events table yet: wait for the run to create it.
            if state != "waiting":
                state = "waiting"
                yield _status(state)
            sleep(poll_seconds)
            continue
        if reset:
            yield _status("reset")
        if state != "live":
            state = "live"
            yield _status(state)
        for row in rows:
            last = row["id"]
            yield f"id: {last}\ndata: {json.dumps(project(row))}\n\n"
        if len(rows) == BATCH:
            continue
        if rows:
            quiet_since = clock()
        elif clock() - quiet_since >= KEEPALIVE_SECONDS:
            quiet_since = clock()
            yield ": keepalive\n\n"
        sleep(poll_seconds)


def _start(value: str | None) -> int:
    try:
        return max(0, int(value or 0))
    except ValueError:
        return 0


def create_app(
    db_path: Path,
    *,
    polls: int | None = None,
    poll_seconds: float = POLL_SECONDS,
    token: str | None = None,
) -> FastAPI:
    token = token or secrets.token_urlsafe(32)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[HOST, "localhost"])

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(_HEADERS)
        return response

    @app.get("/")
    def page() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/app.js")
    def script() -> FileResponse:
        return FileResponse(STATIC / "app.js", media_type="text/javascript")

    @app.get("/arena.js")
    def arena_script() -> FileResponse:
        return FileResponse(STATIC / "arena.js", media_type="text/javascript")

    @app.get("/dashboard.js")
    def dashboard_script() -> FileResponse:
        return FileResponse(STATIC / "dashboard.js", media_type="text/javascript")

    @app.get("/fonts/{name}")
    def font(name: str) -> FileResponse:
        if name not in FONTS:
            raise HTTPException(404)
        return FileResponse(STATIC / "fonts" / name, media_type="font/woff2")

    @app.get("/arena/cycles")
    def arena_cycles(after: str | None = None, run: str | None = None) -> JSONResponse:
        start = _start(after)
        try:
            conn = open_read_only(db_path)
            try:
                page = cycles_after(conn, start, dashboard_feed.pick_run(conn, run))
            finally:
                conn.close()
        except sqlite3.OperationalError:
            # No database yet, or one with no tables yet: nothing to draw until a run creates it.
            page = {"cycles": [], "next_after": start}
        return JSONResponse(page)

    def panel(run: str | None, build, *, needs_run: bool = True) -> JSONResponse:
        """A panel's data for one run. Control and notes belong to the whole database, so the
        operations panel answers before the first cycle too."""
        try:
            conn = open_read_only(db_path)
            try:
                chosen = dashboard_feed.pick_run(conn, run)
                if chosen is None and needs_run:
                    return JSONResponse({"run": None, "runs": []})
                return JSONResponse(build(conn, chosen))
            finally:
                conn.close()
        except sqlite3.OperationalError:
            # No database yet, or one with no tables yet.
            return JSONResponse({"run": None, "runs": []})

    @app.get("/dashboard/scores")
    def scores(run: str | None = None) -> JSONResponse:
        return panel(run, dashboard_feed.scores)

    @app.get("/dashboard/memory")
    def memory(run: str | None = None) -> JSONResponse:
        return panel(run, dashboard_feed.memory)

    @app.get("/dashboard/ops")
    def ops(run: str | None = None) -> JSONResponse:
        def build(conn: sqlite3.Connection, chosen: str | None) -> dict:
            return dashboard_feed.ops(conn, chosen) | {
                "notes_blocked": operator_writes.notes_blocked(conn)
            }

        return panel(run, build, needs_run=False)

    @app.get("/dashboard/token")
    def session_token() -> JSONResponse:
        return JSONResponse({"token": token})

    async def guarded(request: Request) -> dict | JSONResponse:
        """The checks every write passes, or the refusal to send."""
        sent = request.headers.get("x-arena-token", "")
        if not hmac.compare_digest(sent.encode(), token.encode()):
            return JSONResponse({"error": "Missing or wrong token."}, status_code=403)
        origin = request.headers.get("origin")
        if origin is None or origin != f"http://{request.headers.get('host', '')}":
            return JSONResponse({"error": "Writes come from this page only."}, status_code=403)
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            return JSONResponse({"error": "Send JSON."}, status_code=415)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "Send JSON."}, status_code=400)
        return body if isinstance(body, dict) else {}

    @app.post("/control/{action}")
    async def control(action: str, request: Request) -> JSONResponse:
        checked = await guarded(request)
        if isinstance(checked, JSONResponse):
            return checked
        try:
            state = operator_writes.set_control(db_path, action)
        except operator_writes.Refused as refused:
            return JSONResponse({"error": str(refused)}, status_code=refused.status)
        return JSONResponse({"state": state})

    @app.post("/notes")
    async def notes(request: Request) -> JSONResponse:
        checked = await guarded(request)
        if isinstance(checked, JSONResponse):
            return checked
        try:
            note_id = operator_writes.add_note(db_path, checked.get("text"))
        except operator_writes.Refused as refused:
            return JSONResponse({"error": str(refused)}, status_code=refused.status)
        return JSONResponse({"id": note_id})

    @app.get("/events")
    def events(request: Request, after: str | None = None) -> StreamingResponse:
        start = _start(request.headers.get("last-event-id") or after)
        return StreamingResponse(
            stream(db_path, start, polls=polls, poll_seconds=poll_seconds),
            media_type="text/event-stream",
        )

    return app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m arena.server", description="The operator's dashboard, on 127.0.0.1 only."
    )
    parser.add_argument("--db", type=Path, default=None, help="default: the agent database")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args(argv)
    db_path = args.db or agent_db_path()
    print(f"Dashboard for {db_path} at http://{HOST}:{args.port}/")
    uvicorn.run(create_app(db_path), host=HOST, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
