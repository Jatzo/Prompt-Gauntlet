"""Test doubles shared by several test files."""

from collections.abc import Sequence

from arena.llm import CachedOutput


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
