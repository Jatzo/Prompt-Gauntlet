"""The scripted hill-climb control (PLAN section 14, arm C): one-step moves, no model agents.

Each cycle proposes one change to the incumbent: add or remove one normaliser, or add or remove one
rule from a fixed bank. The keep rule decides as it does for the Defender. Moves are tried in a
seeded order, those for the cycle's focus technique first; a move already tried against the same
incumbent is skipped until every move has been, and then the order starts again, since each cycle's
fresh evasions can change the keep decision.

The bank was written from the taxonomy's technique descriptions, one or two rules per known
technique, none for a held-out one and none on the attacker's address: that would be a shortcut the
simulated world rewards (see `placebo.positive_control`), not a defence.
"""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import get_args

import numpy as np

from arena.detector.patch import PatchRefused, apply_patch, fingerprint
from arena.schemas import DefenderPatch, DetectorConfig, NormaliserName, PatchOp, Rule

# (rule id, technique it is written for, pattern). Patterns expect lowercased text.
RULE_BANK: tuple[tuple[str, str, str], ...] = (
    ("hc-zero-width", "obfuscation.zero_width", r"[\u200b\u200c\u200d\u2060\ufeff]"),
    ("hc-encoding", "obfuscation.encoding", r"\b(base64|rot13|decode (this|the following))\b"),
    ("hc-spacing", "obfuscation.spacing", r"\b(?:[a-z] ){4,}[a-z]\b"),
    (
        "hc-leetspeak",
        "obfuscation.leetspeak",
        r"\b[a-z]{0,10}[013457][a-z]{1,10}[013457][a-z]{0,10}\b",
    ),
    ("hc-markdown-image", "exfiltration.markdown", r"!\[[^\]]{0,40}\]\(https?://"),
    ("hc-query-link", "exfiltration.markdown", r"https?://\S{1,80}[?&]\w{1,20}="),
    ("hc-fake-end", "delimiter.fake_end", r"</(document|context|data|email)>|-{3,} ?end of"),
    (
        "hc-override",
        "override.direct",
        r"\b(ignore|disregard|forget) (all |any |the )?(previous|above|prior|earlier)\b",
    ),
    ("hc-persona", "persona.switch", r"\b(you are now|act as|pretend to be)\b"),
    ("hc-tool-call", "tool.argument", r"\b(call|invoke|run) the \w{1,20} tool\b"),
    (
        "hc-summary-aside",
        "indirect.email",
        r"\bwhen (you|the assistant) (summari[sz]e|read)s?\b.{0,60}\b(also|send|forward)\b",
    ),
)
NORMALISERS: tuple[str, ...] = get_args(NormaliserName)


def bank_hash() -> str:
    """Recorded in the manifest, since a bank edit changes what the control can do."""
    return hashlib.sha256(json.dumps(RULE_BANK).encode()).hexdigest()


@dataclass(frozen=True)
class Move:
    label: str
    patch: DefenderPatch
    # The technique a bank rule was written for; None for normaliser moves and removals.
    technique: str | None = None


def _move(label: str, op: PatchOp, technique: str | None = None) -> Move:
    return Move(label, DefenderPatch(ops=[op], rationale=f"Control move: {label}."), technique)


def moves(incumbent: DetectorConfig) -> list[Move]:
    """Every one-step change the patch rules allow. Each one changes the config, since a present
    normaliser or rule is only ever removed and an absent one only ever added."""
    found = []
    for name in NORMALISERS:
        if name in incumbent.normalisers:
            index = incumbent.normalisers.index(name)
            found.append(
                _move(
                    f"remove normaliser {name}", PatchOp(op="remove", path=f"/normalisers/{index}")
                )
            )
        else:
            found.append(
                _move(
                    f"add normaliser {name}", PatchOp(op="add", path="/normalisers/-", value=name)
                )
            )
    present = {rule.id for rule in incumbent.rules}
    for index, rule in enumerate(incumbent.rules):
        found.append(_move(f"remove rule {rule.id}", PatchOp(op="remove", path=f"/rules/{index}")))
    for rule_id, technique, pattern in RULE_BANK:
        if rule_id not in present:
            value = Rule(id=rule_id, pattern=pattern).model_dump(mode="json")
            op = PatchOp(op="add", path="/rules/-", value=value)
            found.append(_move(f"add rule {rule_id}", op, technique))
    if "rules" not in incumbent.layers:
        found = [m for m in found if not m.label.startswith(("add rule", "remove rule"))]
    allowed = []
    for move in found:
        try:
            apply_patch(incumbent, move.patch)
        except PatchRefused:
            continue
        allowed.append(move)
    return allowed


@dataclass
class Choice:
    move: Move | None
    # True when every move had been tried against this incumbent and the order started again.
    restarted: bool = False


def next_move(
    incumbent: DetectorConfig,
    focus: str,
    tried: Iterable[str],
    seed: int,
) -> Choice:
    """The first untried move in a seeded order, the focus technique's rules first."""
    available = moves(incumbent)
    if not available:
        return Choice(None)
    order = np.random.default_rng(seed).permutation(len(available))
    ordered = [available[int(index)] for index in order]
    ordered.sort(key=lambda move: move.technique != focus)
    done = set(tried)
    for move in ordered:
        if move.label not in done:
            return Choice(move)
    return Choice(ordered[0], restarted=True)


def tried_since_restart(history: Iterable[dict], incumbent: DetectorConfig) -> set[str]:
    """Labels already tried against this incumbent, from the run's stored moves in cycle order.
    A restart clears the set, so after one the order is walked again from the start."""
    current = fingerprint(incumbent)
    tried: set[str] = set()
    for record in history:
        if record.get("parent") != current or record.get("label") is None:
            continue
        if record.get("restarted"):
            tried = set()
        tried.add(record["label"])
    return tried
