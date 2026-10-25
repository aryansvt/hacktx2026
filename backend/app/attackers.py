"""shape grouped attacker rows into the attacker_summary contract."""

from typing import Any

from .sessions import fmt_ts

PROFILE = ("kind", "confidence", "reputation", "family", "threat")


def to_row(row: dict[str, Any]) -> dict[str, Any]:
    """store row -> attacker_summary. drops client and anything else not in the profile."""
    return {
        "ip_hash": row["ip_hash"],
        "visits": row["visits"],
        "first_seen": fmt_ts(row["first_seen"]),
        "last_seen": fmt_ts(row["last_seen"]),
        "latest_session_id": row["latest_session_id"],
        "source": row["source"],
        "geo": row["geo"],
        "attacker": {k: row["attacker"][k] for k in PROFILE},
        "session_ids": list(row["session_ids"]),
    }
