"""Token and call accounting, soft alerts and the optional hard cap.

On a subscription plan the constraint is tokens and limit headroom rather than money, so that is
what is tracked. The hard cap is off unless the operator sets one.
"""

import sqlite3

from arena import db
from arena.anomaly import UsageCapReached
from arena.config import DEFAULTS, ArenaConfig


def total_tokens(conn: sqlite3.Connection) -> int:
    query = "SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM usage"
    return conn.execute(query).fetchone()[0]


def check_cap(conn: sqlite3.Connection, config: ArenaConfig = DEFAULTS) -> None:
    """Refuse the next call once the hard cap is used up. Does nothing while the cap is off."""
    if config.hard_cap_tokens is None:
        return
    used = total_tokens(conn)
    if used >= config.hard_cap_tokens:
        raise UsageCapReached(
            f"{used} tokens used, hard cap is {config.hard_cap_tokens}. "
            "Raise the cap or resume after the limit resets.",
            used=used,
            cap=config.hard_cap_tokens,
        )


def record(
    conn: sqlite3.Connection,
    *,
    cycle_id: int,
    role: str,
    model_id: str,
    input_tokens: int,
    output_tokens: int,
    headroom: float | None,
    config: ArenaConfig = DEFAULTS,
) -> None:
    """Store one call's usage and log a soft alert the first time a threshold is crossed."""
    before = total_tokens(conn)
    last_headroom = conn.execute(
        "SELECT headroom FROM usage WHERE headroom IS NOT NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.execute(
        "INSERT INTO usage (cycle_id, role, model_id, input_tokens, output_tokens, headroom,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (cycle_id, role, model_id, input_tokens, output_tokens, headroom, db.now()),
    )
    after = before + input_tokens + output_tokens
    for threshold in config.soft_alert_tokens:
        if before < threshold <= after:
            detail = {"tokens": after, "threshold": threshold}
            db.log_event(conn, "usage_alert", detail, cycle_id=cycle_id)
    floor = config.soft_alert_headroom_fraction
    was_above = last_headroom is None or last_headroom[0] >= floor
    if headroom is not None and headroom < floor and was_above:
        db.log_event(conn, "usage_alert", {"headroom": headroom}, cycle_id=cycle_id)
