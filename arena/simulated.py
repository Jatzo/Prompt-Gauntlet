"""Simulated models for mock mode: deterministic, seeded, and with known answers by construction.

`MockBackend` scripts one output per step, which cannot cover thousands of evaluation items. A
simulated backend instead computes each output from the request and a seed, through a policy per
role. The same request and trial always give the same output, so a measurement on simulated models
has an expected value a test can check, and a rerun is identical.

Policies for the detector and the target app are added beside those packages. Nothing here reads
files or opens a database: everything arrives in the request.
"""

import hashlib
from collections.abc import Callable

import numpy as np

from arena.llm import LLMRequest, LLMResponse, MockBackend

# A policy turns a request and a seeded generator into (tool called, raw JSON output).
Policy = Callable[[LLMRequest, np.random.Generator], tuple[str, str]]


class SimulatedBackend:
    kind = "mock"

    def __init__(
        self,
        policies: dict[str, Policy],
        seed: int,
        model_ids: dict[str, str] | None = None,
        name: str = "simulated",
    ):
        # Part of every evaluation cache key, so it must differ whenever the answers would.
        self.name = f"{name}-{seed}"
        self.policies = policies
        self.seed = seed
        # Lets a test make a role answer as the wrong model.
        self.model_ids = model_ids or {}

    def complete(self, *, role, model_id, step_key, request) -> LLMResponse:
        if role not in self.policies:
            raise RuntimeError(f"No simulated policy for role {role!r}.")
        digest = hashlib.sha256(f"{self.seed}:{role}:{step_key[1]}".encode()).digest()
        rng = np.random.default_rng(int.from_bytes(digest[:8], "big"))
        tool, raw = self.policies[role](request, rng)
        return LLMResponse(
            tool=tool,
            raw_output=raw,
            model_id=self.model_ids.get(role, model_id),
            input_tokens=len(request.system + request.user) // MockBackend.CHARS_PER_TOKEN,
            output_tokens=len(raw) // MockBackend.CHARS_PER_TOKEN,
        )
