"""One stored, dispatched agent call: the only route from an agent's model to the rest of the code.

The model is shown its role's tools and nothing else, its output is stored by `(cycle_id, step)` in
`llm.py`, so a resumed step makes no new call, and the result goes through the dispatcher like any
agent tool call. The arena's orchestrator and part 2's discovery loop both call it.
"""

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pydantic

from arena import dispatcher, llm
from arena.config import ArenaConfig


def system_prompt(root: Path, role: str) -> str:
    """The constitution, then the role's own prompt file."""
    constitution = (root / "constitution.md").read_text()
    prompt = (root / "prompts" / f"{role}.md").read_text()
    return f"{constitution}\n\n{prompt}"


def agent_call[Model: pydantic.BaseModel](
    conn: sqlite3.Connection,
    *,
    backend: llm.Backend,
    config: ArenaConfig,
    root: Path,
    role: str,
    tool: str,
    cycle_id: int,
    step: str,
    response_model: type[Model],
    user: str | None = None,
    check: Callable[[Model], str | None] | None = None,
) -> Model:
    """One forced tool call: the model is shown only its role's tools, and the result goes
    through the dispatcher like any other agent tool call."""
    request = llm.LLMRequest(
        tool=tool,
        tools=dispatcher.tool_schemas_for(role),
        system=system_prompt(root, role),
        user=user or f"Cycle {cycle_id}. Call {tool}.",
    )
    output = llm.call(
        role,
        (cycle_id, step),
        request,
        response_model,
        conn,
        backend=backend,
        config=config,
        check=check,
    )
    dispatched = dispatcher.dispatch(
        conn, role, tool, output.model_dump(mode="json"), cycle_id=cycle_id
    )
    if not isinstance(dispatched, response_model):
        raise TypeError(f"{tool} is registered with a different schema than {response_model}.")
    return dispatched
