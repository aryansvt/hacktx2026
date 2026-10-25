"""raw events, built with the shared contract models so a bad event fails loudly.

events wait in a per-session buffer until the session's source is known
(a guest login turns earlier login_fail events into guest events), then go
to a sink: the jsonl spool, which the sender ships to core. ssh and http both use it.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from hacktx_contracts.raw_event import (
    CommandDetail,
    CommandRawEvent,
    LoginFailDetail,
    LoginFailRawEvent,
    LoginSuccessDetail,
    LoginSuccessRawEvent,
    SessionEndDetail,
    SessionEndRawEvent,
    SessionStartDetail,
    SessionStartRawEvent,
    TripwireDetail,
    TripwireRawEvent,
)

MAX_OUTPUT = 500
MAX_INPUT = 4096
MAX_USERNAME = 256
MAX_BUFFER = 500


class Sink(Protocol):
    def write(self, event: dict) -> None: ...


class JsonlSink:
    """append one json object per line."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")


class MemorySink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def write(self, event: dict) -> None:
        self.events.append(event)


def now_ts() -> str:
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def clean_ip(ip: str) -> str:
    """drop ipv6 zone ids and unwrap ipv4-mapped addresses."""
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


class SessionEvents:
    def __init__(self, sink: Sink, src_ip: str, protocol: str = "ssh", session_id: str | None = None):
        self.sink = sink
        self.src_ip = clean_ip(src_ip)
        self.protocol = protocol
        self.session_id = session_id or uuid.uuid4().hex
        self.source: str | None = None
        self._pending: list[tuple[type, str, str, object]] = []

    def resolve(self, source: str) -> None:
        """fix the source and flush everything buffered so far."""
        if self.source is not None:
            return
        self.source = source
        pending, self._pending = self._pending, []
        for model, kind, ts, detail in pending:
            self._emit(model, kind, ts, detail)

    def session_start(self, client: str | None) -> None:
        self._add(SessionStartRawEvent, "session_start", SessionStartDetail(client=client))

    def login_fail(self, username: str) -> None:
        self._add(LoginFailRawEvent, "login_fail", LoginFailDetail(username=username[:MAX_USERNAME], success=False))

    def login_success(self, username: str) -> None:
        self._add(LoginSuccessRawEvent, "login_success", LoginSuccessDetail(username=username[:MAX_USERNAME], success=True))

    def command(self, line: str, output: str, response_ms: int, answered_by: str = "engine") -> None:
        detail = CommandDetail(
            input=line[:MAX_INPUT],
            output=output[:MAX_OUTPUT],
            response_ms=max(0, int(response_ms)),
            answered_by=answered_by,
        )
        self._add(CommandRawEvent, "command", detail)

    def tripwire(self, tripwire_id: str, reasons: list[str]) -> None:
        self._add(TripwireRawEvent, "tripwire", TripwireDetail(tripwire_id=tripwire_id, reasons=[r[:200] for r in reasons]))

    def session_end(self, duration_s: float, command_count: int) -> None:
        self._add(SessionEndRawEvent, "session_end", SessionEndDetail(duration_s=max(0.0, duration_s), command_count=command_count))

    def _add(self, model: type, kind: str, detail: object) -> None:
        ts = now_ts()
        if self.source is None:
            # a brute forcer can send a lot before login; keep the buffer bounded
            if len(self._pending) < MAX_BUFFER or kind == "session_end":
                self._pending.append((model, kind, ts, detail))
            return
        self._emit(model, kind, ts, detail)

    def _emit(self, model: type, kind: str, ts: str, detail: object) -> None:
        event = model(
            event_id=uuid.uuid4(),
            session_id=self.session_id,
            type=kind,
            timestamp=ts,
            source=self.source,
            protocol=self.protocol,
            src_ip=self.src_ip,
            detail=detail,
        )
        self.sink.write(event.model_dump(mode="json", exclude_none=True))
