"""pure session state logic. a session row is a plain dict so the store and tests share it."""

from datetime import datetime, timezone
from typing import Any

STATUS_RANK = {"approaching": 0, "at_gate": 1, "inside": 2, "ended": 3}


def parse_ts(value: str) -> datetime:
    # contract timestamps always end in Z
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def fmt_ts(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def next_status(current: str, event_type: str) -> str:
    """status only moves forward: approaching -> at_gate -> inside -> ended."""
    if event_type == "session_end":
        target = "ended"
    elif event_type == "login_success":
        target = "inside"
    elif event_type == "login_fail":
        target = "at_gate"
    else:
        return current
    return target if STATUS_RANK[target] > STATUS_RANK[current] else current


def new_row(event: dict[str, Any]) -> dict[str, Any]:
    ts = parse_ts(event["timestamp"])
    return {
        "session_id": event["session_id"],
        "started_at": ts,
        "ended_at": None,
        "last_seen": ts,
        "source": event["source"],
        "protocol": event["protocol"],
        "status": "approaching",
        "login_fails": 0,
        "command_count": 0,
        "breached": False,
        "story": None,
        "geo": event["geo"],
        "attacker": event["attacker"],
    }


def apply_event(row: dict[str, Any] | None, event: dict[str, Any]) -> dict[str, Any]:
    """return the session row after one public event. never mutates the input."""
    row = dict(row) if row else new_row(event)
    ts = parse_ts(event["timestamp"])
    kind = event["type"]
    detail = event.get("detail") or {}

    row["started_at"] = min(row["started_at"], ts)
    # newest event wins for profile fields, so late out of order events don't undo brain
    if ts >= row["last_seen"]:
        row["last_seen"] = ts
        row["attacker"] = event["attacker"]
        row["geo"] = event["geo"]

    row["status"] = next_status(row["status"], kind)
    if kind == "login_fail":
        row["login_fails"] += 1
    elif kind == "login_success":
        row["breached"] = True
    elif kind == "command":
        row["command_count"] += 1
    elif kind == "story":
        row["story"] = detail.get("story")
    elif kind == "session_end":
        row["ended_at"] = ts
        row["command_count"] = max(row["command_count"], detail.get("command_count", 0))
    return row


def to_summary(row: dict[str, Any]) -> dict[str, Any]:
    """session row -> session_summary contract shape."""
    return {
        "session_id": row["session_id"],
        "started_at": fmt_ts(row["started_at"]),
        "ended_at": fmt_ts(row["ended_at"]) if row["ended_at"] else None,
        "source": row["source"],
        "geo": row["geo"],
        "attacker": row["attacker"],
        "status": row["status"],
        "login_fails": row["login_fails"],
        "command_count": row["command_count"],
        "story": row["story"],
    }
