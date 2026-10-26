"""Per-role tool allowlists: the real control on what an agent can do.

Prompts tell an agent which tools it has, but a prompt can be argued with. This cannot: every tool
call an agent makes goes through `dispatch()`, which matches the tool name exactly (no case or
whitespace folding), refuses anything outside the role's list, and pauses the run when it does.
"""

import sqlite3

import pydantic

from arena import db
from arena.anomaly import ForbiddenTool, HijackDetected
from arena.schemas import (
    AttackBatch,
    CEOPlan,
    DefenderPatch,
    DetectorQuery,
    LessonProposal,
    OperatorQuestion,
    PostMortem,
    SourceRequest,
    TechniqueRecord,
)

# Every tool any agent could ever be given, with the schema its arguments must match.
TOOLS: dict[str, type[pydantic.BaseModel]] = {
    "propose_plan": CEOPlan,
    "write_postmortem": PostMortem,
    "propose_lesson": LessonProposal,
    "ask_operator": OperatorQuestion,
    "read_approved_source": SourceRequest,
    "submit_technique_record": TechniqueRecord,
    "submit_attack_batch": AttackBatch,
    "query_detector": DetectorQuery,
    "submit_detector_patch": DefenderPatch,
}

# PLAN.md section 5. The case-study writer and the Judge's grader get no tools.
ALLOWLISTS: dict[str, frozenset[str]] = {
    "ceo": frozenset({"propose_plan", "write_postmortem", "propose_lesson", "ask_operator"}),
    "researcher": frozenset({"read_approved_source", "submit_technique_record"}),
    "attacker": frozenset({"submit_attack_batch", "query_detector"}),
    "defender": frozenset({"submit_detector_patch"}),
    "casestudy": frozenset(),
    "grader": frozenset(),
}


def tool_schemas_for(role: str) -> tuple[dict, ...]:
    """The tool definitions a role's model is shown: its own, and nothing else."""
    return tuple(
        {"name": name, "input_schema": TOOLS[name].model_json_schema()}
        for name in sorted(ALLOWLISTS[role])
    )


def dispatch(
    conn: sqlite3.Connection, role: str, tool_name: str, args: dict, *, cycle_id: int | None = None
) -> pydantic.BaseModel:
    """Validate an agent's tool call and return its typed arguments.

    An unknown role, unknown tool, or tool outside the role's list is recorded as an anomaly,
    pauses the run and raises. Must be called outside any open transaction, so the pause is
    committed even though the caller's work is abandoned.
    """
    allowed = ALLOWLISTS.get(role)
    if allowed is None or tool_name not in allowed:
        detail = {"role": role, "tool": tool_name}
        with db.transaction(conn):
            db.raise_anomaly(conn, ForbiddenTool.kind, detail, cycle_id=cycle_id)
        raise ForbiddenTool(f"{role!r} may not call {tool_name!r}.", recorded=True, **detail)
    try:
        return TOOLS[tool_name].model_validate(args)
    except pydantic.ValidationError as error:
        extra = [e for e in error.errors() if e["type"] == "extra_forbidden"]
        if extra:
            fields = [".".join(map(str, e["loc"])) for e in extra]
            detail = {"role": role, "tool": tool_name, "fields": fields}
            with db.transaction(conn):
                db.raise_anomaly(conn, HijackDetected.kind, detail, cycle_id=cycle_id)
            raise HijackDetected(
                f"{role!r} sent unknown fields to {tool_name!r}.", recorded=True, **detail
            ) from error
        raise
