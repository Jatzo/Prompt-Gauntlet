"""Regex rules with a per-match timeout, which the standard `re` module cannot give.

A rule that times out is disabled for the rest of that evaluation and named, so one pathological
input cannot stall a measurement, and the report says which rule was dropped.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

import regex

from arena.schemas import DetectorConfig, Rule


@dataclass
class RuleSet:
    rules: Sequence[Rule]
    timeout_seconds: float
    disabled: set[str] = field(default_factory=set)

    def __post_init__(self):
        self._compiled = [
            (rule.id, regex.compile(regex.escape(rule.pattern) if rule.literal else rule.pattern))
            for rule in self.rules
        ]

    def matches(self, text: str) -> list[str]:
        """Ids of the rules that match. A rule that times out is disabled, not counted."""
        hits = []
        for rule_id, compiled in self._compiled:
            if rule_id in self.disabled:
                continue
            try:
                if compiled.search(text, timeout=self.timeout_seconds):
                    hits.append(rule_id)
            except TimeoutError:
                self.disabled.add(rule_id)
        return hits


def rule_hits(
    config: DetectorConfig, rule_set: RuleSet, prepared: Sequence[str]
) -> list[list[str]]:
    """The rule ids that fire on each already-normalised text, or none when the config has no rules
    layer. The scorer and the Defender's choice of hard benign cases both use this, so a false
    positive there means exactly what it means in a score."""
    if "rules" not in config.layers:
        return [[] for _ in prepared]
    return [rule_set.matches(text) for text in prepared]
