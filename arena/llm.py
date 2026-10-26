"""The one door every model call goes through.

`call()` stores every raw output keyed by (cycle, step, attempt) before anything else happens to
it. On a resumed cycle the last valid stored output is returned with no call at all, which is what
makes a crash cheap and a rerun deterministic.

Backends:
- mock: scripted outputs, used by tests and the Phase 1 cycle.
- replay: hand-written JSONL cassettes under tests/fixtures/.
- record: wraps live and writes a cassette, only under runs/ or private/ (both gitignored),
  because recorded output can contain anything a model said.
- live: behind ARENA_ALLOW_LIVE=1 and always refused under pytest. Not wired up yet.
"""

import json
import os
import sqlite3
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import pydantic

from arena import db, usage
from arena.anomaly import HijackDetected, ModelIdMismatch, SchemaFailureSpike
from arena.config import DEFAULTS, REPO_ROOT, ArenaConfig


@dataclass(frozen=True)
class LLMRequest:
    # The one tool the model is forced to call, and the only schemas it is shown: its own role's.
    tool: str
    tools: tuple[dict, ...]
    system: str
    user: str


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

    pinned = getattr(config.models, role, None)
    if pinned is None:
        raise ValueError(f"No pinned model for role {role!r}. Add it to ModelIds in config.py.")

    for _ in range(config.retries + 1):
        usage.check_cap(store, config)
        response = backend.complete(role=role, model_id=pinned, step_key=step_key, request=request)
        if response.model_id != pinned:
            _store(
                store, role, step_key, backend, response, failure="wrong_model_id", config=config
            )
            raise ModelIdMismatch(
                f"{role} answered as {response.model_id}, pinned id is {pinned}.",
                role=role,
                expected=pinned,
                reported=response.model_id,
            )
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
            input_tokens=len(request.system + request.user) // 4,
            output_tokens=len(raw) // 4,
        )


class ReplayBackend:
    """Plays back a hand-written cassette: one JSON object per line, matched by (role, step)."""

    name = "replay"

    def __init__(self, cassette: Path):
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
