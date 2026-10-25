"""one-time backfill: rerun the classifier on ended sessions tiger data still has as unknown.

run it with brain/scripts/backfill_classify.py. public events have no raw ip or asn,
so network signals are missing here; everything else the classifier reads is stored.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from hacktx_contracts import parse_event

from . import classifier
from .output import derived_id
from .session import Session, parse_ts
from .worker import EVENTS, EVENTS_MAXLEN

# events the trap saw; brain-made ones (classified, dossier, story) come later and would stretch timing
TRAP_TYPES = {"session_start", "login_fail", "login_success", "command", "tripwire", "session_end"}

UNKNOWN_ENDED = """
select session_id from sessions
where status = 'ended' and attacker->>'kind' = 'unknown'
order by started_at
"""
SESSION_EVENTS = 'select data from events where session_id = $1 order by "timestamp", event_id'


def session_from_events(events: list[dict]) -> Session:
    """rebuild the classifier's view of a session from its stored public events."""
    first = events[0]
    s = Session(first["session_id"], source=first["source"], protocol=first["protocol"])
    for e in events:
        typ, d = e["type"], e.get("detail") or {}
        if typ not in TRAP_TYPES:
            continue
        t = parse_ts(e["timestamp"])
        if s.started_at is None:
            s.started_at = t
        s.last_ts = t
        s.client = s.client or e["attacker"].get("client")
        if typ in ("login_fail", "login_success"):
            s.add_login(t, d.get("username", ""), typ == "login_success")
        elif typ == "command":
            s.add_command(t, d.get("command", ""), d.get("output", ""))
        elif typ == "tripwire":
            s.tripwires.append({"ts": t, "id": d.get("tripwire_id", ""), "reasons": d.get("reasons", [])})
        elif typ == "session_end":
            s.ended = True
    return s


def classified_event(events: list[dict]) -> dict | None:
    """a classified event for the session, or None if it still scores unknown."""
    if not events:
        return None
    verdict = classifier.score(session_from_events(events))
    if verdict.kind == "unknown":
        return None
    latest = events[-1]
    ev = {
        "event_id": derived_id(f"backfill:{latest['session_id']}", "classified"),
        "session_id": latest["session_id"],
        "type": "classified",
        # the latest stored time, so the backend applies it without moving last_seen
        "timestamp": latest["timestamp"],
        "source": latest["source"],
        "protocol": latest["protocol"],
        "geo": latest["geo"],
        "attacker": {**latest["attacker"], "kind": verdict.kind, "confidence": verdict.confidence},
        "detail": {"reasons": verdict.reasons},
    }
    parse_event(ev)
    return ev


async def stored_sessions(pool) -> AsyncIterator[list[dict]]:
    """events of every ended session still unknown, one session at a time, in time order."""
    for row in await pool.fetch(UNKNOWN_ENDED):
        rows = await pool.fetch(SESSION_EVENTS, row["session_id"])
        yield [r["data"] for r in rows]


async def backfill(sessions: AsyncIterator[list[dict]], redis, dry_run: bool = False) -> dict:
    """classify each session; unless dry_run, write new classified events to the events stream."""
    counts = {"checked": 0, "classified": 0, "still_unknown": 0, "by_kind": {}}
    async for events in sessions:
        counts["checked"] += 1
        ev = classified_event(events)
        if ev is None:
            counts["still_unknown"] += 1
            continue
        kind = ev["attacker"]["kind"]
        counts["classified"] += 1
        counts["by_kind"][kind] = counts["by_kind"].get(kind, 0) + 1
        if not dry_run:
            await redis.xadd(EVENTS, {"data": json.dumps(ev)}, maxlen=EVENTS_MAXLEN, approximate=True)
    return counts
