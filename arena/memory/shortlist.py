"""The CEO's focus shortlist, computed by code from the run's memory (PLAN section 9, step 3).

Three signals, each naming one technique, plus the fixed `explore`:
- least tested: the technique this run has focused on in the fewest committed cycles;
- largest miss: the technique with the most evasions shown in the run's recent batches;
- revisit: a technique in the scope of the oldest active lesson.

Ties break by an order seeded from the run's seed, so a rerun gives the same list. A held-out
technique is never a candidate, since it is never named to an agent. A signal with nothing to go on
(no batch yet, no lesson) is left out, and a technique already on the list passes to the next one.

After `plateau_switch_n` committed cycles with no keep, the focus type the last cycle chose leaves
the list, so the CEO has to switch. After `plateau_pause_m` the run pauses (`no_keep_streak`).
"""

import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass

import numpy as np

from arena.config import ArenaConfig
from arena.taxonomy import TECHNIQUES

EXPLORE = "explore"
# A scripted plan's focus that the mock backend replaces with the first focus its prompt lists.
FIRST_LISTED = "{first_listed}"
_LISTED = re.compile(r"^## Focus shortlist[^\n]*\n((?:- [^\n]*\n?)+)", re.MULTILINE)


@dataclass(frozen=True)
class Entry:
    kind: str
    focus: str
    reason: str


@dataclass(frozen=True)
class Shortlist:
    entries: tuple[Entry, ...]
    # The focus type the plateau switch took off the list, if it fired.
    dropped_kind: str | None = None

    @property
    def foci(self) -> tuple[str, ...]:
        return tuple(entry.focus for entry in self.entries)

    def text(self, config: ArenaConfig) -> str:
        lines = [f"- {entry.focus}: {entry.reason}" for entry in self.entries]
        if self.dropped_kind:
            lines.append(
                f"No kept change in {config.plateau_switch_n} or more cycles, so the focus type"
                f" chosen last ({self.dropped_kind}) is off the list this cycle."
            )
        return "## Focus shortlist (pick one)\n" + "\n".join(lines)

    def body(self) -> dict:
        return {
            "entries": [[entry.kind, entry.focus] for entry in self.entries],
            "dropped_kind": self.dropped_kind,
        }


def build(conn: sqlite3.Connection, run_id: str, config: ArenaConfig) -> Shortlist:
    candidates = [t for t in TECHNIQUES if t not in config.held_out_techniques]
    shuffled = [str(t) for t in np.random.default_rng(config.seed).permutation(candidates)]
    rank = {technique: index for index, technique in enumerate(shuffled)}
    committed = _committed(conn, run_id)

    tested = Counter(focus for focus in _foci(conn, committed) if focus in rank)
    missed = _recent_evasions(conn, committed[: config.briefing_recent_experiments])
    least_tested = sorted(rank, key=lambda t: (tested[t], rank[t]))
    largest_miss = sorted((t for t in rank if missed[t]), key=lambda t: (-missed[t], rank[t]))

    entries: list[Entry] = []

    def take(kind: str, ordered, reason) -> None:
        taken = {entry.focus for entry in entries}
        for technique in ordered:
            if technique not in taken:
                entries.append(Entry(kind, technique, reason(technique)))
                return

    take("least_tested", least_tested, lambda t: f"focused on in {tested[t]} cycles of this run")
    take("largest_miss", largest_miss, lambda t: f"{missed[t]} evasions in recent batches")
    for lesson_id, tags in _active_lessons(conn, run_id):
        in_scope = [t for t in shuffled if t in tags or t.split(".")[0] in tags]
        before = len(entries)
        take("revisit", in_scope, lambda t, i=lesson_id: f"in the scope of lesson {i}, the oldest")
        if len(entries) > before:
            break
    entries.append(Entry(EXPLORE, EXPLORE, "attacks outside the known techniques"))

    dropped = None
    if no_keep_streak(conn, run_id) >= config.plateau_switch_n:
        last = _last_kind(conn, committed)
        kept = [entry for entry in entries if entry.kind != last]
        if last and kept:
            entries, dropped = kept, last
    return Shortlist(tuple(entries), dropped)


def listed(prompt: str) -> tuple[str, ...]:
    """The foci a prompt's shortlist section offers, in order; for the scripted and sim agents."""
    found = _LISTED.search(prompt)
    if not found:
        return ()
    return tuple(line[2:].split(":")[0] for line in found.group(1).splitlines())


def no_keep_streak(conn: sqlite3.Connection, run_id: str, *, after_cycle: int = 0) -> int:
    """Committed cycles since this run's last keep, counting only those after `after_cycle`."""
    streak = 0
    for cycle_id in _committed(conn, run_id):
        if cycle_id <= after_cycle:
            break
        row = conn.execute(
            "SELECT json_extract(body, '$.decision') FROM memory_episodic"
            " WHERE cycle_id = ? AND kind = 'judge_report' ORDER BY id DESC LIMIT 1",
            (cycle_id,),
        ).fetchone()
        if row is not None and row[0] == "keep":
            break
        streak += 1
    return streak


def state_of_the_lab(conn: sqlite3.Connection, run_id: str) -> dict:
    """Counts for the plateau pause: dev-side memory only, never a test number."""
    committed = _committed(conn, run_id)
    keeps = sum(
        conn.execute(
            "SELECT 1 FROM memory_episodic WHERE cycle_id = ? AND kind = 'judge_report'"
            " AND json_extract(body, '$.decision') = 'keep'",
            (cycle_id,),
        ).fetchone()
        is not None
        for cycle_id in committed
    )
    return {
        "committed_cycles": len(committed),
        "keeps": keeps,
        "cycles_since_last_keep": no_keep_streak(conn, run_id),
        "foci_tried": dict(Counter(_foci(conn, committed))),
        "active_lessons": len(_active_lessons(conn, run_id)),
    }


def _committed(conn: sqlite3.Connection, run_id: str) -> list[int]:
    """The run's committed cycles, newest first."""
    rows = conn.execute(
        "SELECT id FROM cycles WHERE run_id = ? AND state = 'committed' ORDER BY id DESC",
        (run_id,),
    )
    return [row[0] for row in rows]


def _episodes(conn: sqlite3.Connection, cycles: list[int], kind: str) -> list[dict]:
    bodies = []
    for cycle_id in cycles:
        row = conn.execute(
            "SELECT body FROM memory_episodic WHERE cycle_id = ? AND kind = ?"
            " ORDER BY id DESC LIMIT 1",
            (cycle_id, kind),
        ).fetchone()
        if row is not None:
            bodies.append(json.loads(row[0]))
    return bodies


def _foci(conn: sqlite3.Connection, cycles: list[int]) -> list[str]:
    return [plan["focus"] for plan in _episodes(conn, cycles, "plan")]


def _recent_evasions(conn: sqlite3.Connection, cycles: list[int]) -> Counter:
    """Evasions per technique among those the Judge showed; the held-back half never counts."""
    missed: Counter = Counter()
    for batch in _episodes(conn, cycles, "attack_batch"):
        for verdict in batch["verdicts"]:
            shown = verdict["valid"] and not verdict["held_back"] and not verdict["refused"]
            if shown and verdict["evaded"]:
                missed[verdict["technique"]] += 1
    return missed


def _active_lessons(conn: sqlite3.Connection, run_id: str) -> list[tuple[int, list[str]]]:
    rows = conn.execute(
        "SELECT t.id, t.scope_tags FROM memory_lessons t JOIN cycles c ON c.id = t.cycle_id"
        " WHERE c.run_id = ? AND t.status = 'active' ORDER BY t.id",
        (run_id,),
    )
    return [(row[0], json.loads(row[1])) for row in rows]


def _last_kind(conn: sqlite3.Connection, committed: list[int]) -> str | None:
    shortlists = _episodes(conn, committed[:1], "shortlist")
    plans = _episodes(conn, committed[:1], "plan")
    if not shortlists or not plans:
        return None
    return next(
        (kind for kind, focus in shortlists[0]["entries"] if focus == plans[0]["focus"]), None
    )
