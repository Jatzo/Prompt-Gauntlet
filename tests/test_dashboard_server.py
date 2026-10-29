"""The dashboard's panel endpoints and its only writes: the control flag and operator notes."""

import secrets
import sqlite3

import pytest
from fastapi.testclient import TestClient

from arena import cycle, db, operator_writes, server
from arena.config import DEFAULTS, REPO_ROOT
from arena.memory import briefing

TOKEN = secrets.token_hex(8)
ORIGIN = "http://127.0.0.1"


@pytest.fixture
def path(tmp_path, conn):
    return tmp_path / "arena.db"


def client(path):
    return TestClient(server.create_app(path, token=TOKEN), base_url=ORIGIN)


def post(app, url, body=None, **headers):
    sent = {"X-Arena-Token": TOKEN, "Origin": ORIGIN, "Content-Type": "application/json"}
    sent.update({key.replace("_", "-"): value for key, value in headers.items()})
    sent = {key: value for key, value in sent.items() if value is not None}
    return app.post(url, content=b"{}" if body is None else body, headers=sent)


def open_cycle(conn, run_id="default", state="committed"):
    with db.transaction(conn):
        cycle_id = cycle.open_cycle(conn, run_id)
        conn.execute("UPDATE cycles SET state = ? WHERE id = ?", (state, cycle_id))
    return cycle_id


def test_the_page_may_not_be_framed_or_post_forms(path):
    policy = client(path).get("/").headers["content-security-policy"]
    assert "frame-ancestors 'none'" in policy and "form-action 'none'" in policy


@pytest.mark.parametrize("panel", ["scores", "memory", "ops"])
def test_a_panel_on_a_missing_database_is_empty(tmp_path, panel):
    response = client(tmp_path / "missing.db").get(f"/dashboard/{panel}")
    assert response.status_code == 200 and response.json()["run"] is None


def test_panels_default_to_the_newest_run_and_take_a_run(conn, path):
    open_cycle(conn, "first")
    open_cycle(conn, "second")
    app = client(path)
    assert app.get("/dashboard/scores").json()["run"] == "second"
    assert app.get("/dashboard/scores?run=first").json()["run"] == "first"
    ops = app.get("/dashboard/ops").json()
    assert ops["runs"] == ["second", "first"] and ops["notes_blocked"] is False


def test_the_arena_feed_shows_one_run(conn, path):
    first = open_cycle(conn, "first")
    open_cycle(conn, "second")
    cycles = client(path).get("/arena/cycles?run=first").json()["cycles"]
    assert [c["cycle"] for c in cycles] == [first]


def test_the_token_is_served_to_the_page(path):
    assert client(path).get("/dashboard/token").json() == {"token": TOKEN}


@pytest.mark.parametrize(
    ("action", "state"),
    [("start", "running"), ("pause", "paused"), ("resume", "running"), ("stop", "stopped")],
)
def test_a_control_post_sets_the_flag(conn, path, action, state):
    response = post(client(path), f"/control/{action}")
    assert response.status_code == 200 and response.json() == {"state": state}
    assert db.control_state(conn) == (state, f"operator: {action}")


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"X_Arena_Token": None}, 403),
        ({"X_Arena_Token": "wrong"}, 403),
        ({"Origin": None}, 403),
        ({"Origin": "http://evil.example"}, 403),
        ({"Content_Type": "application/x-www-form-urlencoded"}, 415),
        ({"Content_Type": "text/plain"}, 415),
    ],
)
def test_a_write_without_every_guard_is_refused_and_changes_nothing(conn, path, headers, status):
    before = db.control_state(conn)
    for url in ("/control/pause", "/notes"):
        assert post(client(path), url, b'{"text": "hi"}', **headers).status_code == status
    assert db.control_state(conn) == before
    assert conn.execute("SELECT COUNT(*) FROM memory_operator_notes").fetchone()[0] == 0


def test_a_cross_origin_preflight_gets_no_cors_answer(path):
    response = client(path).options(
        "/notes",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-arena-token",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_an_unknown_action_and_other_methods_are_refused(conn, path):
    app = client(path)
    assert post(app, "/control/delete").status_code == 404
    assert app.put("/notes").status_code == 405
    assert app.delete("/notes").status_code == 405
    assert app.post("/dashboard/scores").status_code == 405


def test_a_note_is_added_through_memory_and_shown(conn, path):
    app = client(path)
    response = post(app, "/notes", b'{"text": "  Look at code samples.  "}')
    assert response.status_code == 200
    [note] = app.get("/dashboard/ops").json()["notes"]
    assert note["text"] == "Look at code samples." and note["id"] == response.json()["id"]


@pytest.mark.parametrize(
    "text", ['""', '"   "', "5", f'"{"x" * (operator_writes.NOTE_CHARS + 1)}"']
)
def test_an_empty_or_too_long_note_is_refused(conn, path, text):
    assert post(client(path), "/notes", f'{{"text": {text}}}'.encode()).status_code == 422


def test_a_note_is_refused_while_a_run_is_mid_cycle_beside_another_run(conn, path):
    open_cycle(conn, "arm-a")
    open_cycle(conn, "arm-b", state="running")
    app = client(path)
    assert app.get("/dashboard/ops").json()["notes_blocked"] is True
    assert post(app, "/notes", b'{"text": "hi"}').status_code == 409


def test_writes_to_a_missing_file_or_an_old_schema_are_refused(tmp_path, conn, path):
    missing = tmp_path / "nothing.db"
    assert post(client(missing), "/control/pause").status_code == 409
    assert not missing.exists()
    with db.transaction(conn):
        conn.execute("UPDATE schema_version SET version = version - 1")
    assert post(client(path), "/control/pause").status_code == 409


def test_a_write_while_the_run_holds_the_lock_answers_busy(conn, path, monkeypatch):
    monkeypatch.setattr(operator_writes, "LOCK_SECONDS", 0.05)
    holder = sqlite3.connect(path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        assert post(client(path), "/control/pause").status_code == 503
    finally:
        holder.execute("ROLLBACK")
        holder.close()


def test_notes_from_the_dashboard_reach_the_next_briefing(conn, path):
    post(client(path), "/notes", b'{"text": "Prefer the code category."}')
    brief = briefing.build(conn, "default", config=DEFAULTS, root=REPO_ROOT)
    assert "- Note 1 (new" in brief.text
    assert brief.new_note_ids == (1,)


def test_no_page_script_writes_markup():
    """The memory panel shows agent text, which may quote an attack. Every script sets text or
    attributes only, so nothing it shows can run as markup."""
    for script in server.STATIC.glob("*.js"):
        source = script.read_text()
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            assert sink not in source, f"{script.name} uses {sink}"
