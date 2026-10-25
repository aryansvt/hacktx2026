"""build public events. every event is checked against the contract before it leaves."""

from __future__ import annotations

import uuid

from hacktx_contracts import parse_event

from .privacy import mask_ip
from .session import Session

# fixed namespace so replays produce the same ids for brain-made events
NS = uuid.UUID("6b1d0f3e-5c2a-4e8b-9a77-0b7e3c1d2f40")
MAX_COMMAND = 2000
MAX_OUTPUT = 500


def derived_id(raw_event_id: str, tag: str) -> str:
    return str(uuid.uuid5(NS, f"{raw_event_id}:{tag}"))


def public_detail(raw: dict, s: Session, techniques: list[str] | None = None) -> dict:
    """map a raw detail to the public one. unknown fields never pass through."""
    typ, d = raw["type"], raw.get("detail", {})
    if typ == "session_start":
        return {"guest_name": d["guest_name"]} if d.get("guest_name") else {}
    if typ in ("login_fail", "login_success"):
        return {"username": d["username"]}
    if typ == "command":
        return {
            "command": mask_ip(d["input"], s.src_ip)[:MAX_COMMAND],
            "output": mask_ip(d["output"], s.src_ip)[:MAX_OUTPUT],
            "response_ms": d["response_ms"],
            "answered_by": d["answered_by"],
            "techniques": techniques or [],
        }
    if typ == "tripwire":
        return {"tripwire_id": d["tripwire_id"], "reasons": list(d.get("reasons", []))}
    if typ == "session_end":
        return {"duration_s": d["duration_s"], "command_count": d["command_count"]}
    raise ValueError(f"unexpected raw type {typ}")


def build(typ: str, s: Session, timestamp: str, detail: dict, event_id: str) -> dict:
    ev = {
        "event_id": event_id,
        "session_id": s.session_id,
        "type": typ,
        "timestamp": timestamp,
        "source": s.source,
        "protocol": s.protocol,
        "geo": s.geo,
        "attacker": s.attacker(),
        "detail": detail,
    }
    parse_event(ev)  # raises if it doesn't match event.schema.json
    return ev
