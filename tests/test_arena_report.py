"""The part 3 report script: its leak check reads every Attacker output and every played attack, and
its report counts them, on tiny made-up databases with no real attack text."""

import importlib.util
import json
import sqlite3

import pytest

from arena.config import REPO_ROOT

_spec = importlib.util.spec_from_file_location(
    "arena_report", REPO_ROOT / "scripts" / "arena_report.py"
)
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)

QUERY = "purple walrus ledger seventeen quietly folded"
BATCH = "orange kettle invoice ninety softly hummed"
REROUTED = "green lantern harbour forty slowly drifted"
PLAYED = "silver otter receipt twelve gently tapped"
T0, T1 = "2026-11-08T10:00:00.000+00:00", "2026-11-08T11:00:00.000+00:00"


@pytest.fixture
def dbs(tmp_path):
    arena_db, judge_db = tmp_path / "arena.db", tmp_path / "judge.db"
    arena = sqlite3.connect(arena_db)
    arena.executescript(
        "CREATE TABLE cycles (id INTEGER, run_id TEXT, state TEXT, created_at TEXT,"
        " updated_at TEXT);"
        "CREATE TABLE llm_calls (cycle_id INTEGER, step TEXT, role TEXT, model_id TEXT,"
        " raw_output TEXT, valid INTEGER, failure TEXT);"
        "CREATE TABLE usage (cycle_id INTEGER, role TEXT, input_tokens INTEGER,"
        " output_tokens INTEGER);"
        "CREATE TABLE events (id INTEGER PRIMARY KEY, cycle_id INTEGER, kind TEXT,"
        " severity TEXT, detail TEXT, created_at TEXT);"
        "CREATE TABLE control (state TEXT, reason TEXT);"
    )
    arena.execute("INSERT INTO cycles VALUES (1, 'a1', 'rolled_back', ?, ?)", (T0, T1))
    calls = [
        ("attack.t0", "m-pinned", json.dumps({"text": QUERY}), 1, None),
        (
            "attack.submit",
            "m-pinned",
            json.dumps({"attacks": [{"text": BATCH, "technique": "x.y"}]}),
            1,
            None,
        ),
        ("attack.t1", "m-other", REROUTED, 0, "wrong_model_id"),
    ]
    arena.executemany("INSERT INTO llm_calls VALUES (1, ?, 'attacker', ?, ?, ?, ?)", calls)
    arena.execute("INSERT INTO usage VALUES (1, 'attacker', 100, 10)")
    arena.execute(
        "INSERT INTO events (cycle_id, kind, severity, detail, created_at) VALUES"
        " (1, 'model_id_mismatch', 'anomaly', ?, ?)",
        (json.dumps({"role": "attacker", "expected": "m-pinned", "reported": "m-other"}), T1),
    )
    arena.execute("INSERT INTO control VALUES ('paused', 'anomaly: model_id_mismatch')")
    arena.commit()
    judge = sqlite3.connect(judge_db)
    judge.executescript(
        "CREATE TABLE attacks (cycle_id INTEGER, idx INTEGER, text TEXT, channel TEXT,"
        " valid INTEGER, refused INTEGER);"
        "CREATE TABLE eval_cache (model_id TEXT, created_at TEXT);"
    )
    judge.execute("INSERT INTO attacks VALUES (1, 0, ?, 'email', 0, 0)", (PLAYED,))
    judge.execute("INSERT INTO attacks VALUES (1, 1, 'another made up text', 'user', 0, 0)")
    judge.executemany(
        "INSERT INTO eval_cache VALUES ('gemma', ?)",
        [("2026-11-08T10:30:00.000+00:00",), ("2026-11-08T12:00:00.000+00:00",)],
    )
    judge.commit()
    return arena_db, judge_db


@pytest.mark.parametrize("planted", [QUERY, BATCH, REROUTED, PLAYED])
def test_check_flags_text_from_every_source(dbs, tmp_path, planted):
    public = tmp_path / "doc.md"
    public.write_text(f"The write-up says: {planted.upper()} in passing.")
    assert report.main(["check", str(public)], *dbs) == 1


def test_check_passes_prose_that_describes_attacks_in_words(dbs, tmp_path):
    public = tmp_path / "doc.md"
    public.write_text("The Attacker wrote meeting notes with an encoded line aimed at the secret.")
    assert report.main(["check", str(public)], *dbs) == 0


def test_the_report_counts_calls_attacks_and_the_cycle_window(dbs):
    figures = report.summary(*dbs, "a1")
    [cycle] = figures["cycles"]
    assert cycle["minutes"] == 60.0
    assert cycle["agent_calls"] == {
        "attacker / m-other / wrong_model_id": 1,
        "attacker / m-pinned / ok": 2,
    }
    assert (cycle["attacks_played"], cycle["attacks_valid"]) == (2, 0)
    assert cycle["channels"] == {"email": 1, "user": 1}
    # Only cache rows written inside the cycle's own window count.
    assert cycle["judge_cache_rows_by_model"] == {"gemma": 1}
    assert cycle["anomalies"][0]["reported"] == "m-other"
    assert figures["control"] == ("paused", "anomaly: model_id_mismatch")


def test_check_reads_a_malformed_batch_whose_attacks_are_plain_strings(dbs, tmp_path):
    arena_db, _ = dbs
    planted = "amber falcon voucher sixty briskly turned"
    conn = sqlite3.connect(arena_db)
    conn.execute(
        "INSERT INTO llm_calls VALUES (1, ?, ?, ?, ?, 0, ?)",
        ("attack.submit", "attacker", "m-pinned", json.dumps({"attacks": [planted]}), "schema"),
    )
    conn.commit()
    public = tmp_path / "doc.md"
    public.write_text(f"Quoted by mistake: {planted}.")
    assert report.main(["check", str(public)], *dbs) == 1
