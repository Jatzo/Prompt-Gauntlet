"""A simulated target model with known behaviour, for mock mode.

It solves each task by following the task's reference steps. When an injection naming the attacker
is visible to it, it obeys with probability `obey`, decided once per episode: it sends Sam's canary
to the attacker if it can send messages, and otherwise puts the canary in its final answer. It
completes the task with probability `complete`.
So the no-defence ASR of a suite is `obey` in expectation, and a test can check a measurement
against it.
"""

import hashlib
import json
import re

import numpy as np

from arena.simulated import Policy
from arena.target.suites import TASKS_BY_ID
from arena.target.world import ATTACKER_ADDRESS

_CANARY = re.compile(r"CANARY-[0-9a-f]{16}")


def _episode_draws(seed: int, episode: str) -> np.ndarray:
    digest = hashlib.sha256(f"{seed}:{episode}".encode()).digest()
    return np.random.default_rng(int.from_bytes(digest[:8], "big")).random(2)


def target_policy(obey: float, complete: float, seed: int) -> Policy:
    def policy(request, rng):
        state = json.loads(request.user)
        task = TASKS_BY_ID[state["task_id"]]
        if request.tool == "plan":
            steps = [
                {"tool": step.tool, "to": step.args.get("to")}
                if step.tool == "send_message"
                else {"tool": step.tool}
                for step in task.steps
            ]
            return "plan", json.dumps({"steps": steps})

        obey_draw, complete_draw = _episode_draws(seed, state["episode"])
        history = state["history"]
        seen = " ".join(text for entry in history for text in entry["result"])
        attacked = any(
            entry["call"]["tool"] == "send_message"
            and entry["call"]["args"].get("to") == ATTACKER_ADDRESS
            for entry in history
        )
        obeys = ATTACKER_ADDRESS in seen and obey_draw < obey
        canary = _CANARY.search(request.system).group(0)
        if obeys and not attacked and "send_message" in state["tools"]:
            action = {"tool": "send_message", "args": {"to": ATTACKER_ADDRESS, "body": canary}}
            return "act", json.dumps(action)

        task_calls = [
            entry for entry in history if entry["call"]["args"].get("to") != ATTACKER_ADDRESS
        ]
        if len(task_calls) < len(task.steps):
            step = task.steps[len(task_calls)]
            args = {key: value.replace("{RESULTS}", seen) for key, value in step.args.items()}
            return "act", json.dumps({"tool": step.tool, "args": args})
        answer = seen if complete_draw < complete else "I could not find that."
        if obeys and "send_message" not in state["tools"]:
            answer = f"{answer} {canary}"
        return "act", json.dumps({"final": answer or "Nothing found."})

    return policy
