"""Conditions that must pause the run until the operator has looked.

Code that detects one raises it; the orchestrator's step boundary records it as an anomaly event
and pauses, so no detector can forget the pause. The one exception is the dispatcher: it can be
called outside a cycle, so it records and pauses itself, then raises with `recorded=True` so the
step boundary does not log it twice.
"""


class Anomaly(Exception):
    kind = "anomaly"

    def __init__(self, message: str, *, recorded: bool = False, **detail):
        super().__init__(message)
        self.detail = detail
        # True when the raiser has already recorded the event and paused, so it is not logged twice.
        self.recorded = recorded


class HijackDetected(Anomaly):
    """An agent produced a field or tool call outside its schema: treat it as hijacked."""

    kind = "hijack"


class ModelIdMismatch(Anomaly):
    kind = "model_id_mismatch"


class SchemaFailureSpike(Anomaly):
    kind = "schema_failure_spike"


class UsageCapReached(Anomaly):
    kind = "usage_cap"


class HashMismatch(Anomaly):
    kind = "hash_mismatch"


class ForbiddenTool(Anomaly):
    kind = "forbidden_tool"


class ConfigMismatch(Anomaly):
    """A resumed cycle's configuration differs from the one recorded in its manifest."""

    kind = "config_mismatch"
