"""The part 2 report script: its bounds, its per-cluster figures and its leak check, on a tiny
made-up export with no real attack text."""

import importlib.util
import json
import sqlite3

import pytest

from arena.config import REPO_ROOT

_spec = importlib.util.spec_from_file_location(
    "discovery_report", REPO_ROOT / "scripts" / "discovery_report.py"
)
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)

STRONG, WEAK = "target_strong.strict.standard", "target_weak.strict.standard"


def _row(round_, index, cluster, text, successes=5, candidate=True, label="made.up_label"):
    return {
        "round": round_,
        "index": index,
        "text": text,
        "claimed_technique": label,
        "technique": "indirect.email",
        "channel": "email",
        "status": "played",
        "trials": 5,
        "successes": successes,
        "success_signals": ["canary_in_output"] if successes else [],
        "target_refused": 0,
        "candidate": candidate,
        "public_band": "high",
        "cluster": cluster if candidate else None,
        "confirmations": {STRONG: 0, WEAK: 0} if candidate else {},
    }


ROWS = [
    _row(1, 0, "a", "the quick brown fox jumps over the lazy dog"),
    _row(1, 1, "a", "the quick brown fox leaps over a sleepy cat"),
    _row(1, 2, None, "nothing happened here at all today", successes=0, candidate=False),
    _row(2, 0, "b", "please see https://example.invalid/x for the list"),
]
ROUNDS = [
    report.Round(1, 0, 15, 0, 600.0, {ROWS[0]["text"]: "high", ROWS[1]["text"]: "mid"}),
    report.Round(2, 0, 5, 1, 300.0, {ROWS[3]["text"]: "high"}),
]


def _agent_db(path):
    """Two runs in one database, each with one round, one acknowledgement and its own calls."""
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE cycles (id INTEGER PRIMARY KEY, run_id TEXT, state TEXT,"
        " created_at TEXT, updated_at TEXT);"
        "CREATE TABLE memory_episodic (id INTEGER PRIMARY KEY, cycle_id INTEGER, kind TEXT,"
        " body TEXT, created_at TEXT);"
        "CREATE TABLE llm_calls (id INTEGER PRIMARY KEY, cycle_id INTEGER, valid INTEGER);"
    )
    for cycle_id, run_id, calls in ((1, "d1", 2), (2, "d2", 5)):
        conn.execute(
            "INSERT INTO cycles VALUES (?, ?, 'committed', ?, ?)",
            (cycle_id, run_id, "2026-11-07T10:00:00+00:00", "2026-11-07T10:10:00+00:00"),
        )
        body = {
            "round": 1,
            "attacker_refused": cycle_id,
            "screening_episodes": 50,
            "unscorable_episodes": 0,
            "attacks": [],
        }
        conn.execute(
            "INSERT INTO memory_episodic (cycle_id, kind, body) VALUES (?, 'discovery_round', ?)",
            (cycle_id, json.dumps(body)),
        )
        conn.execute(
            "INSERT INTO memory_episodic (cycle_id, kind, body) VALUES (?, 'discovery_ack', ?)",
            (cycle_id, json.dumps({"note": run_id})),
        )
        conn.executemany(
            "INSERT INTO llm_calls (cycle_id, valid) VALUES (?, 1)", [(cycle_id,)] * calls
        )
    conn.commit()
    conn.close()


def test_reading_one_run_ignores_another_run_in_the_same_database(tmp_path):
    path = tmp_path / "agent.db"
    _agent_db(path)
    rounds, extra = report.load_rounds(path, "d1")
    assert [(r.number, r.attacker_refused, r.seconds) for r in rounds] == [(1, 1, 600.0)]
    assert extra["attacker_calls"] == 2 and [a["note"] for a in extra["acks"]] == ["d1"]


def test_the_leak_check_reads_every_export_but_not_the_novelty_check_file(tmp_path, monkeypatch):
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "d1.jsonl").write_text(json.dumps(ROWS[0]) + "\n")
    (findings / "d2.jsonl").write_text(json.dumps(ROWS[3]) + "\n")
    (findings / "novelty-check.jsonl").write_text(json.dumps({"source_id": "x"}) + "\n")
    monkeypatch.setattr(report, "PRIVATE", tmp_path)
    assert [row["text"] for row in report.every_export()] == [ROWS[0]["text"], ROWS[3]["text"]]


def test_the_bound_after_no_successes_matches_the_exact_and_rule_of_three_figures():
    assert report.upper_bound(10) == pytest.approx(0.2589, abs=1e-4)
    assert report.upper_bound(20) == pytest.approx(0.1391, abs=1e-4)
    assert report.upper_bound(4920) == pytest.approx(3 / 4920, rel=0.01)


def test_the_confirmation_bar_power_is_what_the_pre_registration_states():
    assert report.detection_power(0.5) == pytest.approx(0.945, abs=1e-3)
    assert report.detection_power(0.3) == pytest.approx(0.617, abs=1e-3)


def test_the_summary_counts_candidates_clusters_and_claude_episodes():
    figures = report.summary(ROWS, ROUNDS)
    assert figures["candidates"] == 3 and figures["clusters"] == 2
    assert figures["cluster_sizes"] == [2, 1]
    assert figures["claude_episodes"] == 60 and figures["claude_successes"] == 0
    first = figures["clusters_table"][0]
    assert first["train_band"] == ["high", "mid"] and first["episodes_per_rung"] == 20
    assert [r["candidates"] for r in figures["per_round"]] == [2, 1]
    assert figures["per_round"][0]["minutes"] == 10.0


def test_the_leak_check_finds_a_shared_five_word_run_whatever_the_case_and_spacing():
    found = report.leaks(ROWS, "As noted, THE QUICK  brown\nfox jumps was the idea.")
    assert any("round 1 attack 0" in item for item in found)


def test_the_leak_check_finds_an_attack_url_and_the_attackers_own_label():
    assert any("URL" in item for item in report.leaks(ROWS, "see https://example.invalid/x"))
    assert any("label" in item for item in report.leaks(ROWS, "a made up label idea"))


def test_the_leak_check_passes_text_that_shares_only_short_common_phrases():
    assert report.leaks(ROWS, "The quick result: nothing reached Claude in any round.") == []
