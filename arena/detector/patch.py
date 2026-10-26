"""Applies a Defender patch to a detector config, or says why it cannot.

The patch is applied to a copy and the result is validated as a whole `DetectorConfig`, so every
cap and safety check the schema holds (rule count, literal rules, nested quantifiers, known
normaliser names) applies to patched configs without a second copy of the rules here.
"""

import hashlib
import json

import pydantic

from arena.schemas import DefenderPatch, DetectorConfig, PatchOp


class PatchRefused(ValueError):
    """The patch cannot be applied, or its result is not a valid detector config."""


def fingerprint(config: DetectorConfig) -> str:
    """SHA-256 of the config's canonical JSON. Two configs that behave alike share no hash unless
    they are identical."""
    canonical = json.dumps(config.model_dump(mode="json"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _apply(data: dict, op: PatchOp) -> None:
    field, *rest = op.path.strip("/").split("/")
    if field == "classifier_prompt":
        if op.op == "remove":
            data[field] = ""
        elif isinstance(op.value, str):
            data[field] = op.value
        else:
            raise PatchRefused("/classifier_prompt takes a string.")
        return
    if not rest:
        if op.op == "remove":
            data[field] = []
        elif isinstance(op.value, list):
            data[field] = op.value
        else:
            raise PatchRefused(f"/{field} takes a list.")
        return
    items, index = data[field], rest[0]
    if index == "-":
        if op.op != "add":
            raise PatchRefused(f"/{field}/- only takes add.")
        items.append(op.value)
        return
    position = int(index)
    limit = len(items) if op.op == "add" else len(items) - 1
    if not 0 <= position <= limit:
        raise PatchRefused(f"/{field}/{position} is out of range ({len(items)} items).")
    if op.op == "add":
        items.insert(position, op.value)
    elif op.op == "remove":
        del items[position]
    else:
        items[position] = op.value


def apply_patch(config: DetectorConfig, patch: DefenderPatch) -> DetectorConfig:
    data = config.model_dump(mode="json")
    for op in patch.ops:
        _apply(data, op)
    try:
        return DetectorConfig.model_validate(data)
    except pydantic.ValidationError as error:
        reasons = "; ".join(
            f"{'/'.join(map(str, problem['loc']))}: {problem['msg']}" for problem in error.errors()
        )
        raise PatchRefused(f"The patched config is not valid: {reasons}") from error
