"""The only way orchestrator code talks to the Judge.

Starts `python -m arena.judge` as a child process and exchanges JSON lines with it. Every reply is
validated against a schema that forbids extra fields, so a per-sample field could not get through
even if the Judge sent one.
"""

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from arena.anomaly import Anomaly
from arena.config import DEFAULTS, REPO_ROOT
from arena.schemas import JudgeReport


class JudgeError(Anomaly):
    """The Judge is dead, hung or refused a request. The run cannot be scored, so it pauses."""

    kind = "judge_unavailable"


class HashReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    constitution: Literal["ok", "mismatch"]
    constitution_hash: str | None
    test_set: Literal["ok", "placeholder", "mismatch", "missing_pin", "missing_test_set"]


class JudgeClient:
    def __init__(
        self,
        root: Path = REPO_ROOT,
        judge_dir: Path | None = None,
        timeout_seconds: float = DEFAULTS.call_timeout_seconds,
    ):
        env = dict(os.environ)
        if judge_dir is not None:
            env["ARENA_JUDGE_DIR"] = str(judge_dir)
        self._process = subprocess.Popen(
            [sys.executable, "-m", "arena.judge", "--root", str(root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            cwd=REPO_ROOT,
            env=env,
            text=True,
        )
        self._timeout = timeout_seconds
        self._next_id = 0
        # Replies are read on a thread so a hung Judge times out instead of blocking for ever.
        self._replies: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._read_replies, daemon=True).start()

    def __enter__(self) -> "JudgeClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._process.stdin.close()
        except BrokenPipeError:
            pass  # The Judge has already exited; there is nothing left to tell it.
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()

    def _read_replies(self) -> None:
        for line in self._process.stdout:
            self._replies.put(line)
        self._replies.put("")  # end of output: the Judge has exited

    def _request(self, method: str, **params) -> dict:
        self._next_id += 1
        line = json.dumps({"id": self._next_id, "method": method, "params": params})
        try:
            self._process.stdin.write(line + "\n")
            self._process.stdin.flush()
            reply_line = self._replies.get(timeout=self._timeout)
        except (BrokenPipeError, OSError) as error:
            raise JudgeError(f"The Judge process is not reachable: {error}") from error
        except queue.Empty as error:
            raise JudgeError(f"The Judge did not answer {method} in {self._timeout}s.") from error
        if not reply_line:
            raise JudgeError("The Judge process closed without replying.")
        try:
            reply = json.loads(reply_line)
        except json.JSONDecodeError as error:
            raise JudgeError(f"The Judge sent a line that is not JSON: {error}") from error
        if reply.get("id") != self._next_id:
            raise JudgeError(
                f"The Judge answered request {reply.get('id')}, expected {self._next_id}."
            )
        if not reply.get("ok"):
            raise JudgeError(f"The Judge refused {method}: {reply.get('error')}")
        return reply["result"]

    def ping(self) -> bool:
        return self._request("ping") == {"pong": True}

    def verify_hashes(self) -> HashReport:
        return HashReport.model_validate(self._request("verify_hashes"))

    def evaluate(self, cycle_id: int) -> JudgeReport:
        return JudgeReport.model_validate(self._request("evaluate", cycle_id=cycle_id))
