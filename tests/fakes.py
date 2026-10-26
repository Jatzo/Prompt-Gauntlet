"""Test doubles shared by several test files."""

import json
import re
from collections.abc import Callable, Sequence

from arena.llm import CachedOutput, LLMResponse


class MemoryEvalCache:
    """An in-memory EvalCacheStore, so a test needs no Judge database."""

    def __init__(self):
        self.outputs: dict[str, CachedOutput] = {}

    def lookup_many(self, keys: Sequence[str]) -> dict[str, CachedOutput]:
        return {key: self.outputs[key] for key in keys if key in self.outputs}

    def store_many(self, outputs: Sequence[CachedOutput]) -> None:
        for output in outputs:
            self.outputs[output.key] = output

    def tokens(self) -> tuple[int, int]:
        return (
            sum(output.input_tokens for output in self.outputs.values()),
            sum(output.output_tokens for output in self.outputs.values()),
        )


_DATA = re.compile(r"<<<DATA [0-9a-f]+>>>\n(.*)\n<<<END DATA [0-9a-f]+>>>", re.S)


def keyword_verdict(text: str) -> dict:
    """A crude labeller: an attack when the text names the attacker placeholder or says ignore."""
    lowered = text.lower()
    if "{attacker}" in lowered or "ignore" in lowered:
        return {"label": "attack", "kind": "injection", "impact_class": "data_theft"}
    return {"label": "benign", "kind": "neither", "impact_class": "none"}


class FakeLabeller:
    """A labeller backend that reads the datamarked text and answers with `judge(text)`."""

    def __init__(self, name: str, judge: Callable[[str], dict] = keyword_verdict):
        self.name, self.judge, self.calls = name, judge, 0

    def complete(self, *, role, model_id, step_key, request):
        self.calls += 1
        text = _DATA.search(request.user).group(1).replace("^", " ")
        return LLMResponse(
            tool=request.tool, raw_output=json.dumps(self.judge(text)), model_id=model_id
        )
