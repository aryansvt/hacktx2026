"""per-session state, kept in a redis hash with a ttl."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone

MAX_COMMANDS = 300
MAX_LOGINS = 200
MAX_OUTPUT = 300


def parse_ts(ts: str) -> float:
    """utc 'Z' timestamp -> epoch seconds."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def fmt_ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class Session:
    session_id: str
    source: str = "wild"
    protocol: str = "ssh"
    src_ip: str = ""  # core only, never emitted
    ip_hash: str | None = None
    client: str | None = None
    guest_name: str | None = None
    geo: dict | None = None
    asn_org: str | None = None
    asn_category: str | None = None
    started_at: float | None = None
    last_ts: float | None = None
    status: str = "approaching"
    logins: list = field(default_factory=list)  # {ts, username, success}
    commands: list = field(default_factory=list)  # {ts, input, output}
    tripwires: list = field(default_factory=list)  # {ts, id, reasons}
    downloads: list = field(default_factory=list)
    written: list = field(default_factory=list)  # files written by hand, e.g. echo > x
    techniques: list = field(default_factory=list)
    kind: str = "unknown"
    confidence: float = 0.0
    reasons: list = field(default_factory=list)
    cls_kind: str = "unknown"  # last emitted classification
    cls_conf: float = 0.0
    reputation: str = "unknown"
    family: str | None = None
    threat: str = "low"
    threat_base: str = "low"
    lookups_done: list = field(default_factory=list)
    dossiers: list = field(default_factory=list)  # {target_kind, reputation, family, summary}
    command_count: int = 0
    ended: bool = False
    story: str | None = None

    @property
    def login_fails(self) -> int:
        return sum(1 for x in self.logins if not x["success"])

    @property
    def logged_in(self) -> bool:
        return any(x["success"] for x in self.logins) or bool(self.commands)

    def add_command(self, ts: float, line: str, output: str) -> None:
        self.commands.append({"ts": ts, "input": line, "output": output[:MAX_OUTPUT]})
        del self.commands[:-MAX_COMMANDS]
        self.command_count += 1

    def add_login(self, ts: float, username: str, success: bool) -> None:
        self.logins.append({"ts": ts, "username": username, "success": success})
        del self.logins[:-MAX_LOGINS]

    def observe(self, raw: dict) -> None:
        """fold one raw event's facts into the session (no enrichment)."""
        t = parse_ts(raw["timestamp"])
        typ, d = raw["type"], raw.get("detail", {})
        if self.started_at is None:
            self.started_at = t
        self.last_ts = t
        if typ == "session_start":
            self.client = d.get("client") or self.client
            self.guest_name = d.get("guest_name") or self.guest_name
        elif typ in ("login_fail", "login_success"):
            self.add_login(t, d.get("username", ""), typ == "login_success")
            if typ == "login_success":
                self.status = "inside"
            elif self.status == "approaching":
                self.status = "at_gate"
        elif typ == "command":
            self.add_command(t, d.get("input", ""), d.get("output", ""))
            self.status = "inside"
        elif typ == "tripwire":
            self.tripwires.append({"ts": t, "id": d.get("tripwire_id", ""), "reasons": d.get("reasons", [])})
        elif typ == "session_end":
            self.ended = True
            self.status = "ended"

    def attacker(self) -> dict:
        return {
            "kind": self.kind,
            "confidence": self.confidence,
            "reputation": self.reputation,
            "family": self.family,
            "threat": self.threat,
            "client": self.client,
            "ip_hash": self.ip_hash,
        }

    def to_hash(self) -> dict[str, str]:
        return {k: json.dumps(v) for k, v in asdict(self).items()}

    @classmethod
    def from_hash(cls, h: dict) -> "Session":
        names = {f.name for f in fields(cls)}
        data = {}
        for k, v in h.items():
            k = k.decode() if isinstance(k, bytes) else k
            if k in names:
                data[k] = json.loads(v)
        return cls(**data)


class SessionStore:
    def __init__(self, redis, ttl_s: int = 86400, prefix: str = "brain:session:"):
        self.r = redis
        self.ttl = ttl_s
        self.prefix = prefix

    def key(self, session_id: str) -> str:
        return self.prefix + session_id

    async def get(self, session_id: str) -> Session | None:
        h = await self.r.hgetall(self.key(session_id))
        return Session.from_hash(h) if h else None

    async def save(self, s: Session) -> None:
        k = self.key(s.session_id)
        async with self.r.pipeline(transaction=True) as p:
            p.hset(k, mapping=s.to_hash())
            p.expire(k, self.ttl)
            await p.execute()
