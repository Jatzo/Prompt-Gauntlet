import json
import threading
import time

import pydantic
import pytest

from arena import llm
from arena.anomaly import ModelIdMismatch, UsageCapReached
from arena.config import DEFAULTS, ArenaConfig
from arena.llm import KeyedRequest, MemoryEvalCache, Unscorable
from arena.schemas import DetectorResult
from arena.simulated import SimulatedBackend

VALID = json.dumps({"score": 80.0, "label": "attack", "reasons": ["asks to send data"]})


def request(text: str, temperature: float = 0.0) -> llm.LLMRequest:
    return llm.LLMRequest(
        tool="report_score", tools=(), system="score it", user=text, temperature=temperature
    )


def keyed(item_id: str, text: str, trial: int = 0) -> KeyedRequest:
    return KeyedRequest(item_id=item_id, trial=trial, request=request(text))


class CountingBackend:
    """Answers from a function of the request, and counts calls per user text. Thread-safe."""

    name = "counting"

    def __init__(self, answer=lambda request: ("report_score", VALID), model_id=None):
        self.answer = answer
        self.model_id = model_id
        self.calls: dict[str, int] = {}
        self._lock = threading.Lock()

    def complete(self, *, role, model_id, step_key, request):
        with self._lock:
            self.calls[request.user] = self.calls.get(request.user, 0) + 1
        tool, raw = self.answer(request)
        return llm.LLMResponse(
            tool=tool,
            raw_output=raw,
            model_id=self.model_id or model_id,
            input_tokens=10,
            output_tokens=5,
        )


def batch(requests, cache, backend, config=DEFAULTS):
    return llm.call_batch(
        "detector", requests, DetectorResult, cache, backend=backend, config=config
    )


def test_results_come_back_in_request_order_and_validated():
    backend = CountingBackend()
    results = batch([keyed("a", "one"), keyed("b", "two")], MemoryEvalCache(), backend)
    assert [type(result) for result in results] == [DetectorResult, DetectorResult]
    assert backend.calls == {"one": 1, "two": 1}


def test_identical_requests_share_one_call():
    backend = CountingBackend()
    results = batch([keyed("a", "same"), keyed("b", "same")], MemoryEvalCache(), backend)
    assert len(results) == 2
    assert backend.calls == {"same": 1}


def test_a_rerun_against_the_same_cache_makes_no_calls():
    cache = MemoryEvalCache()
    batch([keyed("a", "one"), keyed("b", "two")], cache, CountingBackend())
    again = CountingBackend()
    batch([keyed("a", "one"), keyed("b", "two")], cache, again)
    assert again.calls == {}


def test_a_different_trial_is_a_different_call():
    backend = CountingBackend()
    batch([keyed("a", "one", trial=0), keyed("a", "one", trial=1)], MemoryEvalCache(), backend)
    assert backend.calls == {"one": 2}


@pytest.mark.parametrize(
    "change",
    [
        lambda r: llm.LLMRequest(r.tool, r.tools, r.system + " v2", r.user, r.temperature),
        lambda r: llm.LLMRequest(r.tool, ({"name": "x"},), r.system, r.user, r.temperature),
        lambda r: llm.LLMRequest(r.tool, r.tools, r.system, r.user, 0.7),
        lambda r: llm.LLMRequest("other_tool", r.tools, r.system, r.user, r.temperature),
    ],
    ids=["system", "tools", "temperature", "tool"],
)
def test_any_change_to_the_rendered_request_changes_the_key(change):
    base = keyed("a", "text")
    changed = KeyedRequest(item_id="a", trial=0, request=change(base.request))
    model = DEFAULTS.models.detector
    assert llm.request_key("detector", model, base, "x") != llm.request_key(
        "detector", model, changed, "x"
    )


def test_the_item_id_alone_does_not_change_the_key():
    model = DEFAULTS.models.detector
    first = llm.request_key("detector", model, keyed("a", "text"), "x")
    assert first == llm.request_key("detector", model, keyed("b", "text"), "x")


def test_a_schema_failure_is_retried_then_comes_back_unscorable_and_is_cached():
    backend = CountingBackend(answer=lambda r: ("report_score", '{"score": 900}'))
    cache = MemoryEvalCache()
    config = ArenaConfig(retries=2)
    [result] = batch([keyed("a", "bad")], cache, backend, config)
    assert isinstance(result, Unscorable) and result.reason.startswith("schema")
    assert backend.calls == {"bad": 3}
    again = CountingBackend()
    batch([keyed("a", "bad")], cache, again, config)
    assert again.calls == {}


def test_an_output_outside_its_schema_is_unscorable_kept_as_evidence_and_not_retried():
    smuggled = json.dumps(
        {"score": 1.0, "label": "benign", "reasons": [], "send_to": "x@example.invalid"}
    )
    backend = CountingBackend(answer=lambda r: ("report_score", smuggled))
    cache = MemoryEvalCache()
    [result] = batch([keyed("a", "attack text")], cache, backend)
    assert isinstance(result, Unscorable) and result.reason.startswith("hijack")
    assert backend.calls == {"attack text": 1}
    [stored] = cache.outputs.values()
    assert stored.raw_output == smuggled and not stored.valid


def test_many_broken_items_never_raise_or_pause():
    backend = CountingBackend(answer=lambda r: ("wrong_tool", VALID))
    results = batch([keyed(str(i), f"t{i}") for i in range(60)], MemoryEvalCache(), backend)
    assert all(isinstance(result, Unscorable) for result in results)


def test_a_response_from_an_unpinned_model_raises():
    backend = CountingBackend(model_id="claude-imposter")
    with pytest.raises(ModelIdMismatch):
        batch([keyed("a", "one")], MemoryEvalCache(), backend)


def test_misses_run_concurrently_and_keep_their_order():
    config = ArenaConfig(detector_concurrency=8)

    def echo(request):
        score = float(request.user)
        label = "attack" if score > 50 else "benign"
        return "report_score", json.dumps({"score": score, "label": label, "reasons": []})

    results = batch(
        [keyed(str(i), str(i)) for i in range(100)],
        MemoryEvalCache(),
        CountingBackend(echo),
        config,
    )
    assert [result.score for result in results] == [float(i) for i in range(100)]


def test_the_simulated_backend_is_deterministic_per_key_and_seed():
    def policy(request, rng):
        score = float(rng.integers(0, 101))
        return "report_score", json.dumps({"score": score, "label": "benign", "reasons": []})

    def run(seed, trial):
        backend = SimulatedBackend({"detector": policy}, seed=seed)
        [result] = batch([keyed("a", "text", trial=trial)], MemoryEvalCache(), backend)
        return result.score

    assert run(1, 0) == run(1, 0)
    assert len({run(1, trial) for trial in range(10)}) > 1
    assert len({run(seed, 0) for seed in range(10)}) > 1


def test_a_cached_output_that_no_longer_validates_raises():
    cache = MemoryEvalCache()
    batch([keyed("a", "one")], cache, CountingBackend())
    [key] = cache.outputs
    cache.outputs[key] = llm.CachedOutput(
        key=key,
        item_id="a",
        raw_output='{"score": 900}',
        valid=True,
        failure=None,
        model_id=DEFAULTS.models.detector,
        input_tokens=0,
        output_tokens=0,
    )
    with pytest.raises(pydantic.ValidationError):
        batch([keyed("a", "one")], cache, CountingBackend())


def test_a_failed_call_keeps_every_finished_call_in_the_cache():
    def answer(request):
        if request.user == "bad":
            raise ConnectionError("network down")
        return "report_score", VALID

    cache = MemoryEvalCache()
    requests = [keyed(f"i{n}", f"text {n}") for n in range(20)] + [keyed("x", "bad")]
    one_worker = ArenaConfig(detector_concurrency=1)
    with pytest.raises(ConnectionError):
        batch(requests, cache, CountingBackend(answer), config=one_worker)

    again = CountingBackend()
    results = batch(requests, cache, again, config=one_worker)
    assert again.calls == {"bad": 1}
    assert all(isinstance(result, DetectorResult) for result in results)


def test_the_hard_cap_stops_evaluation_calls_and_keeps_what_was_spent():
    cache = MemoryEvalCache()
    capped = ArenaConfig(detector_concurrency=1, hard_cap_tokens=45)
    requests = [keyed(f"i{n}", f"text {n}") for n in range(5)]
    backend = CountingBackend()
    with pytest.raises(UsageCapReached):
        batch(requests, cache, backend, config=capped)
    assert len(backend.calls) == 3 and cache.tokens() == (30, 15)

    # The cap counts what the cache already holds, so a rerun under it makes no call.
    again = CountingBackend()
    with pytest.raises(UsageCapReached):
        batch(requests, cache, again, config=capped)
    assert again.calls == {}


def test_answers_from_one_backend_are_never_reused_by_another():
    cache = MemoryEvalCache()
    batch([keyed("a", "one")], cache, CountingBackend())
    live = CountingBackend()
    live.name = "live"
    batch([keyed("a", "one")], cache, live)
    assert live.calls == {"one": 1}


def test_a_failed_cache_write_stops_the_queue_instead_of_draining_it(monkeypatch):
    class FullDisk(MemoryEvalCache):
        def store_many(self, outputs):
            if outputs:
                raise OSError("disk full")

    def slow(request):
        time.sleep(0.01)
        return "report_score", VALID

    monkeypatch.setattr(llm, "_STORE_EVERY", 5)
    backend = CountingBackend(slow)
    requests = [keyed(f"i{n}", f"text {n}") for n in range(50)]
    with pytest.raises(OSError, match="disk full"):
        batch(requests, FullDisk(), backend, config=ArenaConfig(detector_concurrency=1))
    assert sum(backend.calls.values()) < 10


def test_a_failing_call_with_work_still_queued_raises_instead_of_hanging():
    def first_fails(request):
        time.sleep(0.01)
        if request.user == "text 0":
            raise ConnectionError("network down")
        return "report_score", VALID

    backend = CountingBackend(first_fails)
    requests = [keyed(f"i{n}", f"text {n}") for n in range(20)]
    raised = []

    def run():
        try:
            batch(requests, MemoryEvalCache(), backend, config=ArenaConfig(detector_concurrency=1))
        except ConnectionError as error:
            raised.append(error)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "call_batch hung after a failed call"
    assert raised and sum(backend.calls.values()) < 20


def test_two_replay_cassettes_do_not_share_cached_answers(tmp_path):
    entry = {"role": "detector", "step": "s", "tool": "report_score", "model_id": "m"}
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    first.write_text(json.dumps({**entry, "raw_output": VALID}))
    second.write_text(json.dumps({**entry, "raw_output": VALID.replace("80.0", "10.0")}))
    assert llm.ReplayBackend(first).name != llm.ReplayBackend(second).name
