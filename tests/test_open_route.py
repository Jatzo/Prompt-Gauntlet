"""Open-weights roles inside a live run: routed to a local Ollama backend, keyed by its digest,
held to its own model id, and never needed by a run that uses only Claude."""

import json

import pytest
from fakes import MemoryEvalCache

from arena import llm
from arena.anomaly import ModelIdMismatch
from arena.config import DEFAULTS
from arena.llm import KeyedRequest, OpenRoute, Unscorable
from arena.schemas import DetectorResult

VALID = json.dumps({"score": 80.0, "label": "attack", "reasons": ["asks to send data"]})


def keyed(item_id: str) -> KeyedRequest:
    schema = {"name": "report_score", "input_schema": DetectorResult.model_json_schema()}
    request = llm.LLMRequest(
        tool="report_score", tools=(schema,), system="score it", user=item_id, temperature=0.0
    )
    return KeyedRequest(item_id=item_id, trial=0, request=request)


class Answering:
    """Answers every call with a valid score, as the model it names."""

    def __init__(self, model_id: str):
        self.model_id, self.calls = model_id, []

    def complete(self, *, role, model_id, step_key, request):
        self.calls.append(role)
        return llm.LLMResponse("report_score", VALID, self.model_id, 10, 5)


class Routed:
    """A live-shaped backend: Claude roles answer here, open roles through an OpenRoute."""

    name = "live"
    safeguard_fallback = True

    def __init__(self, open_route: OpenRoute):
        self.claude, self._open = Answering("claude-haiku-5-5"), open_route

    def name_for(self, role):
        return self._open.name if role in llm.OPEN_WEIGHTS_ROLES else self.name

    def complete(self, *, role, model_id, step_key, request):
        if role in llm.OPEN_WEIGHTS_ROLES:
            return self._open.complete(
                role=role, model_id=model_id, step_key=step_key, request=request
            )
        return self.claude.complete(
            role=role, model_id=model_id, step_key=step_key, request=request
        )


def batch(role, backend, cache):
    return llm.call_batch(
        role,
        [keyed("a"), keyed("b")],
        DetectorResult,
        cache,
        backend=backend,
        refusals_are_items=True,
    )


def test_the_open_backend_is_made_on_its_first_call_and_only_then():
    made = []
    gemma = Answering(DEFAULTS.models.target_open)
    route = OpenRoute(make=lambda: made.append(1) or gemma)
    backend = Routed(route)
    batch("detector", backend, MemoryEvalCache())
    assert made == [] and gemma.calls == []
    batch("target_open", backend, MemoryEvalCache())
    batch("target_open", backend, MemoryEvalCache())
    assert made == [1] and gemma.calls == ["target_open"] * 4


def test_open_answers_are_keyed_and_stored_under_the_digest_and_never_as_refusals():
    gemma = Answering(DEFAULTS.models.target_open)
    backend, cache = Routed(OpenRoute(make=lambda: gemma)), MemoryEvalCache()
    results = batch("target_open", backend, cache)
    assert not any(isinstance(result, Unscorable) for result in results)
    stored = list(cache.outputs.values())
    assert {output.backend for output in stored} == {llm.open_backend_name()}
    assert all(output.failure is None for output in stored)
    assert backend.claude.calls == []


def test_another_model_answering_an_open_role_stops_the_run_instead_of_counting_as_refusals():
    backend = Routed(OpenRoute(make=lambda: Answering("gemma4:27b")))
    cache = MemoryEvalCache()
    with pytest.raises(ModelIdMismatch, match="gemma4:27b"):
        batch("target_open", backend, cache)
    assert not any(output.failure == llm.REFUSED for output in cache.outputs.values())


def test_claude_roles_keep_their_own_keys_and_the_fallback():
    backend, cache = Routed(OpenRoute(make=lambda: Answering("unused"))), MemoryEvalCache()
    batch("detector", backend, cache)
    assert {output.backend for output in cache.outputs.values()} == {"live"}
    assert llm._takes_fallback(backend, "detector")
    assert not llm._takes_fallback(backend, "target_open")


def test_the_live_backend_sends_open_roles_to_the_route_and_claude_roles_elsewhere(monkeypatch):
    gemma = Answering(DEFAULTS.models.target_open)
    live = object.__new__(llm.LiveBackend)
    live._open = OpenRoute(make=lambda: gemma)

    async def no_claude(model_id, request):
        raise AssertionError("an open role reached Claude")

    monkeypatch.setattr(live, "_complete", no_claude)
    request = keyed("a").request
    live.complete(role="target_open", model_id="gemma4:12b", step_key=(0, "k"), request=request)
    assert gemma.calls == ["target_open"]
    assert live.name_for("target_open") == llm.open_backend_name()
    assert live.name_for("detector") == "live"


class Server:
    def __init__(self, prompt_tokens: int):
        self.prompt_tokens = prompt_tokens

    def __call__(self, url, body):
        if url.endswith("/api/tags"):
            return {"models": [{"name": "gemma4:12b", "digest": "abc123def4567890"}]}
        return {
            "model": "gemma4:12b",
            "message": {"content": VALID},
            "done_reason": "stop",
            "prompt_eval_count": self.prompt_tokens,
            "eval_count": 9,
        }


def test_a_prompt_that_filled_the_context_window_is_refused_and_not_stored():
    backend = llm.OllamaBackend(digest="abc123def4567890", num_ctx=100, post=Server(100))
    cache = MemoryEvalCache()
    with pytest.raises(llm.LiveCallFailed, match="context window"):
        batch("target_open", backend, cache)
    assert cache.outputs == {}
    fits = llm.OllamaBackend(digest="abc123def4567890", num_ctx=100, post=Server(99))
    assert not any(isinstance(r, Unscorable) for r in batch("target_open", fits, cache))
