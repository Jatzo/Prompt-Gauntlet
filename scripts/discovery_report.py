"""Prints every figure in docs/discovery.md from part 2's private files, and checks public files for
attack text before they are committed.

The findings export (`discover export`) holds the attacks, so it stays in private/. This script
reads it, the Attacker's round records and the agent database, and `report` prints counts only:
tables in Markdown, ready to compare with the write-up.

`check` is the leak gate. It decodes every attack text in every findings export, folds case and
whitespace, and flags any run of 5 words that also appears in a given file. What it prints is only
words already present in the checked file. It also flags any URL from an attack text and any of
the Attacker's own technique labels, since those name the working idea more exactly than the docs
should. A plain substring search would miss attack text that the export stores escaped.

Usage, from the repo root:
  python scripts/discovery_report.py report [RUN_ID]          (default d1)
  python scripts/discovery_report.py check FILE [FILE ...]    (exit 1 on any match)
"""

# Each Markdown table row is printed from one line, so it reads like the row it prints.
# ruff: noqa: E501

import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from math import comb
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRIVATE = ROOT / "private"
AGENT_DB = ROOT / "runs" / "discovery-agent.db"
RUNGS = {"target_strong.strict.standard": "rung 0", "target_weak.strict.standard": "rung 1"}
ROUND_SIZE = 10
PILOT_ROUNDS = 3
# Words in a shared run before it counts as leaked text. Five is the novelty measure's own n.
LEAK_WORDS = 5
# The six largest clusters hold one idea, read by hand; the figure tracks their share per round.
LARGEST = 6
SIGNALS = ("canary_in_output", "canary_in_tool_arg", "fetched_attacker_url", "sent_to_attacker")


def upper_bound(trials: int, confidence: float = 0.95) -> float:
    """The exact one-sided upper bound on a rate after 0 successes in `trials`. The rule of three,
    3 / trials, is its large-sample approximation."""
    return 1 - (1 - confidence) ** (1 / trials)


def detection_power(rate: float, trials: int = 10, needed: int = 3) -> float:
    """The chance that a candidate with this true rate reaches the confirmation bar on one target."""
    return sum(
        comb(trials, k) * rate**k * (1 - rate) ** (trials - k) for k in range(needed, trials + 1)
    )


@dataclass(frozen=True)
class Round:
    number: int
    attacker_refused: int
    screening_episodes: int
    unscorable_episodes: int
    seconds: float
    # The band each played attack's text got in the Attacker's feedback, against train and the run.
    bands: dict[str, str]


def load_rows(run_id: str) -> list[dict]:
    path = PRIVATE / "findings" / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def every_export() -> list[dict]:
    """The attacks of every run exported so far. The novelty check's per-item file holds ids and
    bands, not attacks, so it is skipped."""
    rows = []
    for path in sorted((PRIVATE / "findings").glob("*.jsonl")):
        if path.name != "novelty-check.jsonl":
            rows += load_rows(path.stem)
    return rows


def load_rounds(agent_db: Path, run_id: str) -> tuple[list[Round], dict]:
    conn = sqlite3.connect(f"file:{agent_db}?mode=ro", uri=True)
    times = {
        cycle_id: (datetime.fromisoformat(created), datetime.fromisoformat(updated))
        for cycle_id, created, updated in conn.execute(
            "SELECT id, created_at, updated_at FROM cycles WHERE run_id = ?", (run_id,)
        )
    }
    rounds = []
    for cycle_id, body in conn.execute(
        "SELECT m.cycle_id, m.body FROM memory_episodic m JOIN cycles c ON c.id = m.cycle_id"
        " WHERE m.kind = 'discovery_round' AND c.run_id = ? ORDER BY m.id",
        (run_id,),
    ):
        record = json.loads(body)
        start, end = times[cycle_id]
        rounds.append(
            Round(
                record["round"],
                record["attacker_refused"],
                record["screening_episodes"],
                record["unscorable_episodes"],
                (end - start).total_seconds(),
                {a["text"]: a["band"] for a in record["attacks"] if a.get("band")},
            )
        )
    calls = conn.execute(
        "SELECT COUNT(*), SUM(l.valid) FROM llm_calls l JOIN cycles c ON c.id = l.cycle_id"
        " WHERE c.run_id = ?",
        (run_id,),
    ).fetchone()
    acks = [
        json.loads(body)
        for (body,) in conn.execute(
            "SELECT m.body FROM memory_episodic m JOIN cycles c ON c.id = m.cycle_id"
            " WHERE m.kind = 'discovery_ack' AND c.run_id = ?",
            (run_id,),
        )
    ]
    conn.close()
    return rounds, {"attacker_calls": calls[0], "attacker_valid": calls[1], "acks": acks}


def clusters(rows: list[dict]) -> list[list[dict]]:
    """Candidate clusters, largest first, ties by first round."""
    grouped = defaultdict(list)
    for row in rows:
        if row["candidate"]:
            grouped[row["cluster"]].append(row)
    return sorted(grouped.values(), key=lambda c: (-len(c), min(r["round"] for r in c)))


def summary(rows: list[dict], rounds: list[Round]) -> dict:
    """Every figure the write-up quotes, from the export rows and the round records."""
    by_round = {r.number: r for r in rounds}
    candidates = [row for row in rows if row["candidate"]]
    groups = clusters(rows)
    largest = {group[0]["cluster"] for group in groups[:LARGEST]}
    train_band = {}
    for row in rows:
        record = by_round.get(row["round"])
        train_band[(row["round"], row["index"])] = record.bands.get(row["text"]) if record else None
    per_round = []
    for number in sorted(by_round):
        played = [row for row in rows if row["round"] == number]
        hits = [row for row in played if row["candidate"]]
        signals = Counter(s for row in played for s in row["success_signals"])
        per_round.append(
            {
                "round": number,
                "asked": ROUND_SIZE,
                "played": len(played),
                "rejected": sum(row["status"] == "rejected" for row in played),
                "held_out": sum(row["status"] == "held_out" for row in played),
                "attacker_refused": by_round[number].attacker_refused,
                "episodes": by_round[number].screening_episodes,
                "unscorable": by_round[number].unscorable_episodes,
                "target_refused": sum(row["target_refused"] for row in played),
                "successful_trials": sum(row["successes"] for row in played),
                "signals": {s: signals[s] for s in SIGNALS},
                "candidates": len(hits),
                "claude_successes": sum(sum(row["confirmations"].values()) for row in hits),
                "minutes": round(by_round[number].seconds / 60, 1),
                "largest_share": (
                    sum(row["cluster"] in largest for row in hits) / len(hits) if hits else 0.0
                ),
            }
        )
    table = []
    for number, group in enumerate(groups, start=1):
        n = len(group)
        table.append(
            {
                "cluster": f"C{number}",
                "technique": Counter(r["technique"] for r in group).most_common(1)[0][0],
                "channels": sorted({r["channel"] for r in group}),
                "candidates": n,
                "rounds": (min(r["round"] for r in group), max(r["round"] for r in group)),
                "gemma_5_of_5": sum(r["successes"] == r["trials"] for r in group),
                "train_band": sorted(
                    {train_band[(r["round"], r["index"])] or "none" for r in group}
                ),
                "public_band": sorted({r["public_band"] for r in group}),
                **{
                    label: sum(r["confirmations"][key] for r in group)
                    for key, label in RUNGS.items()
                },
                "episodes_per_rung": 10 * n,
                "bound_per_rung": upper_bound(10 * n),
                "bound_pooled": upper_bound(20 * n),
            }
        )
    pilot = [r for r in rounds if r.number <= PILOT_ROUNDS]
    pilot_episodes = sum(r.screening_episodes for r in pilot)
    claude_episodes = 20 * len(candidates)
    return {
        "asked": ROUND_SIZE * len(rounds),
        "played": len(rows),
        "attacker_refused": sum(r.attacker_refused for r in rounds),
        "short_rounds": [r.number for r in rounds if r.attacker_refused],
        "episodes": sum(r.screening_episodes for r in rounds),
        "unscorable": sum(r.unscorable_episodes for r in rounds),
        "target_refused": sum(row["target_refused"] for row in rows),
        "candidates": len(candidates),
        "clusters": len(groups),
        "cluster_sizes": [len(g) for g in groups],
        "signals": {s: sum(s in row["success_signals"] for row in candidates) for s in SIGNALS},
        "gemma_successes": Counter(row["successes"] for row in candidates),
        "claude_episodes": claude_episodes,
        "claude_successes": sum(sum(row["confirmations"].values()) for row in candidates),
        "bound_pooled_all": upper_bound(claude_episodes),
        "bound_single_per_rung": upper_bound(10),
        "bound_single_pooled": upper_bound(20),
        "power": {rate: detection_power(rate) for rate in (0.5, 0.3, 0.1)},
        "pilot": {
            "episodes": pilot_episodes,
            "unscorable_share": sum(r.unscorable_episodes for r in pilot) / pilot_episodes,
            "attacker_refused_share": sum(r.attacker_refused for r in pilot)
            / (ROUND_SIZE * len(pilot)),
        },
        "per_round": per_round,
        "clusters_table": table,
    }


def print_report(figures: dict, extra: dict) -> None:
    top = {k: v for k, v in figures.items() if k not in ("per_round", "clusters_table")}
    print(
        json.dumps(
            {**top, **{k: v for k, v in extra.items() if k != "acks"}}, indent=1, default=str
        )
    )
    print("\nPilot acknowledgement:", [a["note"] for a in extra["acks"]])
    print(
        "\n| Round | Asked | Played | Rejected | Held out | Attacker refused | Episodes | Unscorable "
        "| Target refused | Successful trials | Candidates | Claude successes | Minutes |"
    )
    print("|" + "---|" * 13)
    for r in figures["per_round"]:
        print(
            f"| {r['round']} | {r['asked']} | {r['played']} | {r['rejected']} | {r['held_out']} "
            f"| {r['attacker_refused']} | {r['episodes']} | {r['unscorable']} "
            f"| {r['target_refused']} | {r['successful_trials']} | {r['candidates']} "
            f"| {r['claude_successes']} | {r['minutes']} |"
        )
    print("\nSignals per round:", [(r["round"], r["signals"]) for r in figures["per_round"]])
    print(
        f"Share of candidates in the {LARGEST} largest clusters, per round:",
        [(r["round"], round(r["largest_share"], 2)) for r in figures["per_round"]],
    )
    print(
        "\n| Cluster | Technique | Channels | Candidates | Rounds | Gemma 5 of 5 | Band (train, run) "
        "| Band (public) | Rung 0 | Rung 1 | Bound per rung | Bound pooled |"
    )
    print("|" + "---|" * 12)
    for c in figures["clusters_table"]:
        print(
            f"| {c['cluster']} | {c['technique']} | {', '.join(c['channels'])} | {c['candidates']} "
            f"| {c['rounds'][0]} to {c['rounds'][1]} | {c['gemma_5_of_5']} "
            f"| {', '.join(c['train_band'])} | {', '.join(c['public_band'])} "
            f"| {c['rung 0']} of {c['episodes_per_rung']} | {c['rung 1']} of {c['episodes_per_rung']} "
            f"| {c['bound_per_rung']:.1%} | {c['bound_pooled']:.2%} |"
        )


def _fold(text: str) -> list[str]:
    return re.findall(r"[a-z0-9{}@.:/_-]+", text.lower())


def _runs(words: list[str]) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + LEAK_WORDS]) for i in range(len(words) - LEAK_WORDS + 1)}


def leaks(rows: list[dict], public_text: str) -> list[str]:
    """What in `public_text` comes from the attacks: shared 5-word runs, attack URLs and the
    Attacker's own labels. Empty means clean."""
    found = []
    public_words = _fold(public_text)
    public_runs = _runs(public_words)
    flat = " ".join(public_words)
    for row in rows:
        shared = _runs(_fold(row["text"])) & public_runs
        found += [
            f"round {row['round']} attack {row['index']}: '{' '.join(run)}'" for run in shared
        ]
        for url in re.findall(r"https?://\S+", row["text"]):
            if url.lower().rstrip(".,)") in public_text.lower():
                found.append(f"round {row['round']} attack {row['index']}: an attack URL")
        label = " ".join(re.split(r"[._\-\s]+", row["claimed_technique"].lower())).strip()
        if len(label.split()) >= 2 and label in " ".join(re.split(r"[._\-\s]+", flat)):
            found.append(f"round {row['round']} attack {row['index']}: the Attacker's label")
    return sorted(set(found))


def main(argv: list[str]) -> int:
    if argv[:1] == ["check"] and len(argv) > 1:
        rows = every_export()
        if not rows:
            print("No findings export in private/findings, so there is nothing to check against.")
            return 2
        dirty = 0
        for name in argv[1:]:
            found = leaks(rows, Path(name).read_text())
            dirty += len(found)
            print(f"{name}: {'clean' if not found else f'{len(found)} matches'}")
            for item in found[:20]:
                print("  ", item)
        return 1 if dirty else 0
    if argv[:1] == ["report"]:
        run_id = argv[1] if len(argv) > 1 else "d1"
        rounds, extra = load_rounds(AGENT_DB, run_id)
        print_report(summary(load_rows(run_id), rounds), extra)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
