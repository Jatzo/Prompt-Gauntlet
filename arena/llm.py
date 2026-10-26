"""Every model call goes through this module, by one of two doors.

`call()` is the door for agent steps. It stores every raw output keyed by (cycle, step, attempt)
before anything else happens to it, and on a resumed cycle returns the last valid stored output
with no call at all, which is what makes a crash cheap and a rerun deterministic.

`call_batch()` is the door for evaluation: detector scores and target-app turns, thousands per
experiment. Each call is keyed by the hash of its fully rendered request plus the trial number, so
a change to the prompt, tools, model or conversation can never reuse a stale answer, and a rerun of
the same measurement makes no calls. Both doors share one validation rule and one model-id check.

Backends:
- mock: scripted outputs, used by tests and the Phase 1 cycle.
- replay: hand-written JSONL cassettes under tests/fixtures/.
- record: wraps live and writes a cassette, only under runs/ or private/ (both gitignored),
  because recorded output can contain anything a model said.
- live: behind ARENA_ALLOW_LIVE=1 and always refused under pytest. Not wired up yet.
"""

import contextlib
import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from collections import deque
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import pydantic

from arena import db, usage
from arena.anomaly import HijackDetected, ModelIdMismatch, SchemaFailureSpike, UsageCapReached
from arena.config import DEFAULTS, REPO_ROOT, ArenaConfig


@dataclass(frozen=True)
class LLMRequest:
    # The one tool the model is forced to call, and the only schemas it is shown: its own role's.
    tool: str
    tools: tuple[dict, ...]
    system: str
    user: str
    # Part of every evaluation cache key, and sent to the live model.
    temperature: float = 0.0


@dataclass(frozen=True)
class LLMResponse:
    tool: str
    raw_output: str
    model_id: str
    input_tokens: int = 0
    output_tokens: int = 0
    # Share of the plan's rate limit still available, when the backend reports it.
    headroom: float | None = None


class Backend(Protocol):
    name: str

    def complete(
        self, *, role: str, model_id: str, step_key: tuple[int, str], request: LLMRequest
    ) -> LLMResponse: ...


class SchemaFailure(RuntimeError):
    """Every attempt at a step produced output that did not validate."""


class LiveCallRefused(RuntimeError):
    pass


class ReplayMiss(RuntimeError):
    pass


def call[Model: pydantic.BaseModel](
    role: str,
    step_key: tuple[int, str],
    request: LLMRequest,
    response_model: type[Model],
    store: sqlite3.Connection,
    *,
    backend: Backend,
    config: ArenaConfig = DEFAULTS,
) -> Model:
    """Return the validated output for this step, calling the model only if none is stored.

    `store` is the agent database for agent calls and the Judge database for anything the Judge
    runs, so per-sample test output can never land where memory or briefing code reads.
    """
    cycle_id, step = step_key
    stored = store.execute(
        "SELECT raw_output FROM llm_calls WHERE cycle_id = ? AND step = ? AND valid = 1"
        " ORDER BY attempt DESC LIMIT 1",
        (cycle_id, step),
    ).fetchone()
    if stored is not None:
        return response_model.model_validate_json(stored[0])

    pinned = _pinned_model(role, config)
    for _ in range(config.retries + 1):
        usage.check_cap(store, config)
        response = backend.complete(role=role, model_id=pinned, step_key=step_key, request=request)
        if response.model_id != pinned:
            _store(
                store, role, step_key, backend, response, failure="wrong_model_id", config=config
            )
            raise _wrong_model(role, pinned, response)
        parsed, failure = _validate(response, request, response_model)
        _store(store, role, step_key, backend, response, failure=failure, config=config)
        if parsed is not None:
            return parsed
        if failure.startswith("hijack"):
            raise HijackDetected(
                f"{role} output at step {step} went outside its schema: {failure}",
                role=role,
                step=step,
            )
        _check_failure_rate(store, role, config)

    raise SchemaFailure(
        f"{role} produced no valid output for step {step} in {config.retries + 1} attempts."
    )


def _pinned_model(role: str, config: ArenaConfig) -> str:
    pinned = getattr(config.models, role, None)
    if pinned is None:
        raise ValueError(f"No pinned model for role {role!r}. Add it to ModelIds in config.py.")
    return pinned


def _wrong_model(role: str, pinned: str, response: LLMResponse) -> ModelIdMismatch:
    return ModelIdMismatch(
        f"{role} answered as {response.model_id}, pinned id is {pinned}.",
        role=role,
        expected=pinned,
        reported=response.model_id,
    )


def _validate[Model: pydantic.BaseModel](
    response: LLMResponse, request: LLMRequest, response_model: type[Model]
) -> tuple[Model | None, str | None]:
    """Return (parsed, None) or (None, reason).

    An unknown tool or an unknown field is a hijack; a bad value in a known field is an ordinary
    schema failure. The difference is whether the model stayed inside the shape it was given.
    """
    if response.tool != request.tool:
        return None, f"hijack: called tool {response.tool!r}"
    try:
        return response_model.model_validate_json(response.raw_output), None
    except pydantic.ValidationError as error:
        problems = error.errors()
        extra = [".".join(map(str, p["loc"])) for p in problems if p["type"] == "extra_forbidden"]
        if extra:
            return None, f"hijack: unknown fields {extra}"
        return None, f"schema: {problems[0]['type']} at {problems[0]['loc']}"


def _store(
    store: sqlite3.Connection,
    role: str,
    step_key: tuple[int, str],
    backend: Backend,
    response: LLMResponse,
    *,
    failure: str | None,
    config: ArenaConfig,
) -> None:
    cycle_id, step = step_key
    with db.transaction(store):
        attempt = store.execute(
            "SELECT COALESCE(MAX(attempt), 0) + 1 FROM llm_calls WHERE cycle_id = ? AND step = ?",
            (cycle_id, step),
        ).fetchone()[0]
        store.execute(
            "INSERT INTO llm_calls (cycle_id, step, attempt, role, model_id, backend, raw_output,"
            " valid, failure, input_tokens, output_tokens, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cycle_id,
                step,
                attempt,
                role,
                response.model_id,
                backend.name,
                response.raw_output,
                int(failure is None),
                failure,
                response.input_tokens,
                response.output_tokens,
                db.now(),
            ),
        )
        usage.record(
            store,
            cycle_id=cycle_id,
            role=role,
            model_id=response.model_id,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            headroom=response.headroom,
            config=config,
        )


@dataclass(frozen=True)
class KeyedRequest:
    """One evaluation call. `item_id` is kept for evidence; the cache key ignores it, so two items
    with identical rendered requests share one answer."""

    item_id: str
    trial: int
    request: LLMRequest


@dataclass(frozen=True)
class Unscorable:
    """No valid output after every attempt, or an output outside its schema. The caller counts it
    against the defence; it never raises, because attack texts will try to break the classifier."""

    reason: str


@dataclass(frozen=True)
class CachedOutput:
    """The final result for one cache key, valid or not. Invalid output is kept as evidence."""

    key: str
    item_id: str
    raw_output: str
    valid: bool
    failure: str | None
    model_id: str
    input_tokens: int
    output_tokens: int
    # The backend that answered, so usage can be priced per backend.
    backend: str = ""


class EvalCacheStore(Protocol):
    """Where evaluation outputs live. The Judge's database implements it; llm.py names no table."""

    def lookup_many(self, keys: Sequence[str]) -> dict[str, CachedOutput]: ...

    def store_many(self, outputs: Sequence[CachedOutput]) -> None: ...

    def tokens(self) -> tuple[int, int]: ...


def request_key(role: str, model_id: str, keyed: KeyedRequest, backend: str) -> str:
    """SHA-256 of everything that decides the answer: the backend, role, pinned model, the rendered
    request and the trial number. The backend is in the key so a simulated or mock answer is never
    reused by a live run, nor one simulated profile's answer by another."""
    request = keyed.request
    rendered = json.dumps(
        {
            "backend": backend,
            "role": role,
            "model_id": model_id,
            "tool": request.tool,
            "tools": request.tools,
            "system": request.system,
            "user": request.user,
            "temperature": request.temperature,
            "trial": keyed.trial,
        },
        sort_keys=True,
    )
    return hashlib.sha256(rendered.encode()).hexdigest()


# Finished calls call_batch holds before writing them: a killed run loses at most this many.
_STORE_EVERY = 200


def call_batch[Model: pydantic.BaseModel](
    role: str,
    requests: Sequence[KeyedRequest],
    response_model: type[Model],
    cache: EvalCacheStore,
    *,
    backend: Backend,
    config: ArenaConfig = DEFAULTS,
) -> list[Model | Unscorable]:
    """Results in the order of `requests`. A cached key makes no call, valid or not.

    Unlike `call()`, a schema failure or an out-of-schema output on one item does not raise and does
    not count towards the schema-failure pause: the item comes back `Unscorable`. A wrong model id
    still raises, because that is a configuration fault rather than an item fault. Misses run on a
    thread pool; only the calling thread writes the cache, in chunks as calls finish. When a call
    raises, the queued calls are cancelled, every finished one is stored, and then the error is
    raised, so a rerun pays only for what did not finish.

    The hard cap counts the cache's own tokens: the Judge's database is separate from the agents'
    usage table, and each database is capped on its own.
    """
    pinned = _pinned_model(role, config)
    keys = [request_key(role, pinned, keyed, backend.name) for keyed in requests]
    outputs = cache.lookup_many(list(dict.fromkeys(keys)))
    missing: dict[str, KeyedRequest] = {}
    for key, keyed in zip(keys, requests, strict=True):
        if key not in outputs:
            missing.setdefault(key, keyed)

    cap = config.hard_cap_tokens
    spent = [sum(cache.tokens()) if cap is not None else 0]
    spent_lock = threading.Lock()

    def attempt(key: str, keyed: KeyedRequest) -> CachedOutput:
        for _ in range(config.retries + 1):
            if cap is not None:
                with spent_lock:
                    if spent[0] >= cap:
                        raise UsageCapReached(
                            f"{spent[0]} evaluation tokens used, hard cap is {cap}. "
                            "Raise the cap or resume after the limit resets.",
                            used=spent[0],
                            cap=cap,
                        )
            response = backend.complete(
                role=role, model_id=pinned, step_key=(0, key), request=keyed.request
            )
            with spent_lock:
                spent[0] += response.input_tokens + response.output_tokens
            if response.model_id != pinned:
                raise _wrong_model(role, pinned, response)
            parsed, failure = _validate(response, keyed.request, response_model)
            output = CachedOutput(
                key=key,
                item_id=keyed.item_id,
                raw_output=response.raw_output,
                valid=parsed is not None,
                failure=failure,
                model_id=response.model_id,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                backend=backend.name,
            )
            # A hijack is not retried: asking again only gives the attack another go.
            if parsed is not None or failure.startswith("hijack"):
                break
        return output

    if missing:
        unstored: list[CachedOutput] = []
        error: Exception | None = None

        def store() -> None:
            cache.store_many(unstored)
            outputs.update({output.key: output for output in unstored})
            unstored.clear()
            # Progress for long runs. stderr only: the Judge's stdout carries its JSON replies.
            done = sum(key in outputs for key in missing)
            print(f"{role}: {done}/{len(missing)} new calls stored", file=sys.stderr)

        pool = ThreadPoolExecutor(max_workers=config.detector_concurrency)
        read: set[Future] = set()
        try:
            futures = [pool.submit(attempt, key, keyed) for key, keyed in missing.items()]
            for future in as_completed(futures):
                read.add(future)
                try:
                    unstored.append(future.result())
                except Exception as failure:
                    error = failure
                    # Stop reading here: as_completed never yields a future that shutdown
                    # cancels, so reading on would wait forever.
                    break
                if len(unstored) >= _STORE_EVERY:
                    store()
        except BaseException:
            # Ctrl-C or a failed cache write: stop the queue spending, keep what finished if the
            # cache still takes it, and report the original error.
            pool.shutdown(wait=False, cancel_futures=True)
            with contextlib.suppress(Exception):
                store()
            raise
        # After an error this cancels the queue and waits only for calls already running.
        pool.shutdown(cancel_futures=True)
        unstored += [
            future.result()
            for future in futures
            if future not in read
            and future.done()
            and not future.cancelled()
            and future.exception() is None
        ]
        store()
        if error is not None:
            raise error

    results: list[Model | Unscorable] = []
    for key in keys:
        output = outputs[key]
        if output.valid:
            results.append(response_model.model_validate_json(output.raw_output))
        else:
            results.append(Unscorable(output.failure or "invalid"))
    return results


def schema_failure_rate(
    store: sqlite3.Connection, role: str, config: ArenaConfig = DEFAULTS
) -> tuple[float, int]:
    """Failure share over the role's most recent calls, and how many calls that covers.

    Only calls after the role's last spike pause count. Otherwise the failures that caused the pause
    would still fill the window after the operator resumes, and the next single failure would pause
    the run again.
    """
    since = store.execute(
        "SELECT COALESCE(MAX(created_at), '') FROM events"
        " WHERE kind = 'schema_failure_spike' AND json_extract(detail, '$.role') = ?",
        (role,),
    ).fetchone()[0]
    rows = store.execute(
        "SELECT valid FROM llm_calls WHERE role = ? AND created_at > ? ORDER BY id DESC LIMIT ?",
        (role, since, config.schema_failure_window),
    ).fetchall()
    if not rows:
        return 0.0, 0
    return sum(1 for row in rows if not row[0]) / len(rows), len(rows)


def _check_failure_rate(store: sqlite3.Connection, role: str, config: ArenaConfig) -> None:
    rate, calls = schema_failure_rate(store, role, config)
    if calls >= config.schema_failure_min_calls and rate >= config.schema_failure_pause_rate:
        raise SchemaFailureSpike(
            f"{role} failed schema validation on {rate:.0%} of its last {calls} calls.",
            role=role,
            rate=rate,
            calls=calls,
        )


@dataclass
class MockBackend:
    """Scripted outputs per step, consumed in order. Each entry is raw JSON or (tool, raw JSON).

    `call_log` appends one line per call and fsyncs it, so a test can count calls across a killed
    process. `block_at_step` writes `block_marker` and then waits forever without logging, which
    lets a test kill the process at a known point.
    """

    script: dict[str, list]
    model_ids: dict[str, str] = field(default_factory=dict)
    call_log: Path | None = None
    block_at_step: str | None = None
    block_marker: Path | None = None
    name: str = "mock"
    # A rough average for English text, good enough for usage accounting in tests.
    CHARS_PER_TOKEN = 4

    def __post_init__(self):
        self._queues = {step: deque(outputs) for step, outputs in self.script.items()}

    @classmethod
    def from_env(cls, script: dict[str, list]) -> "MockBackend":
        def path(name: str) -> Path | None:
            value = os.environ.get(name)
            return Path(value) if value else None

        return cls(
            script=script,
            call_log=path("ARENA_MOCK_CALL_LOG"),
            block_at_step=os.environ.get("ARENA_MOCK_BLOCK_AT_STEP") or None,
            block_marker=path("ARENA_MOCK_BLOCK_MARKER"),
        )

    def complete(self, *, role, model_id, step_key, request):
        cycle_id, step = step_key
        if step == self.block_at_step:
            if self.block_marker is not None:
                self.block_marker.write_text(f"{cycle_id} {step}\n")
            while True:
                time.sleep(60)
        queue = self._queues.get(step)
        if not queue:
            raise RuntimeError(f"Mock script has no output left for step {step!r}.")
        entry = queue.popleft()
        tool, raw = entry if isinstance(entry, tuple) else (request.tool, entry)
        if self.call_log is not None:
            with self.call_log.open("a") as log:
                log.write(json.dumps({"cycle": cycle_id, "step": step, "role": role}) + "\n")
                log.flush()
                os.fsync(log.fileno())
        return LLMResponse(
            tool=tool,
            raw_output=raw,
            model_id=self.model_ids.get(role, model_id),
            input_tokens=len(request.system + request.user) // self.CHARS_PER_TOKEN,
            output_tokens=len(raw) // self.CHARS_PER_TOKEN,
        )


class ReplayBackend:
    """Plays back a hand-written cassette: one JSON object per line, matched by (role, step)."""

    def __init__(self, cassette: Path):
        # Part of every evaluation cache key, so two cassettes never share cached answers.
        digest = hashlib.sha256(cassette.read_bytes()).hexdigest()[:8]
        self.name = f"replay-{digest}"
        self._entries: dict[tuple[str, str], deque] = {}
        for number, line in enumerate(cassette.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            missing = {"role", "step", "tool", "raw_output", "model_id"} - entry.keys()
            if missing:
                raise ValueError(f"{cassette}:{number} is missing {sorted(missing)}")
            self._entries.setdefault((entry["role"], entry["step"]), deque()).append(entry)

    def complete(self, *, role, model_id, step_key, request):
        queue = self._entries.get((role, step_key[1]))
        if not queue:
            raise ReplayMiss(f"Cassette has no entry for role {role!r} at step {step_key[1]!r}.")
        entry = queue.popleft()
        return LLMResponse(
            tool=entry["tool"],
            raw_output=entry["raw_output"],
            model_id=entry["model_id"],
            input_tokens=entry.get("input_tokens", 0),
            output_tokens=entry.get("output_tokens", 0),
        )


class LiveBackend:
    """The real model. Refused in tests and unless the operator sets ARENA_ALLOW_LIVE=1.

    Not wired up in Phase 1: the operator checks the plan's terms for automated use first.
    """

    name = "live"

    def __init__(self):
        if os.environ.get("PYTEST_CURRENT_TEST"):
            raise LiveCallRefused("Live model calls are never made from tests. Use mock or replay.")
        if os.environ.get("ARENA_ALLOW_LIVE") != "1":
            raise LiveCallRefused("Live calls are off. Set ARENA_ALLOW_LIVE=1 to allow them.")

    def complete(self, *, role, model_id, step_key, request):
        raise NotImplementedError("The live backend is not wired up yet.")


class RecordBackend:
    """Wraps another backend and writes each response to a cassette under runs/ or private/."""

    name = "record"
    allowed_roots = ("runs", "private")

    def __init__(self, inner: Backend, cassette: Path):
        resolved = cassette.resolve()
        if not any(resolved.is_relative_to(REPO_ROOT / root) for root in self.allowed_roots):
            raise ValueError(
                f"Recordings may only be written under runs/ or private/, not {cassette}."
            )
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self.inner = inner
        self.cassette = resolved

    def complete(self, *, role, model_id, step_key, request):
        response = self.inner.complete(
            role=role, model_id=model_id, step_key=step_key, request=request
        )
        entry = {
            "role": role,
            "step": step_key[1],
            "tool": response.tool,
            "raw_output": response.raw_output,
            "model_id": response.model_id,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
        }
        with self.cassette.open("a") as out:
            out.write(json.dumps(entry) + "\n")
        return response


def get_backend(
    name: str | None = None,
    *,
    mock_script: dict[str, list] | None = None,
    cassette: Path | None = None,
) -> Backend:
    name = name or os.environ.get("ARENA_LLM_BACKEND", "mock")
    if name == "mock":
        return MockBackend.from_env(mock_script or {})
    if name == "replay":
        if cassette is None:
            raise ValueError("Replay needs a cassette path.")
        return ReplayBackend(cassette)
    if name == "live":
        return LiveBackend()
    if name == "record":
        if cassette is None:
            raise ValueError("Record needs a cassette path under runs/ or private/.")
        return RecordBackend(LiveBackend(), cassette)
    raise ValueError(f"Unknown backend {name!r}. Use mock, replay, record or live.")
