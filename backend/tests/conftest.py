import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import fakeredis
import pytest
from jsonschema import Draft202012Validator

from app.config import Settings
from app.main import create_app
from app.sessions import apply_event, fmt_ts

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
EXAMPLES = CONTRACTS / "examples"
TOKEN = "test-token"


def load_example(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS / f"{name}.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def make_event(
    type_: str,
    session_id: str = "ssh-test",
    ts: datetime | None = None,
    source: str = "wild",
    kind: str = "bot",
    reputation: str = "malicious",
    country: str = "NL",
    detail: dict | None = None,
) -> dict:
    """valid public event of any type."""
    defaults = {
        "session_start": {},
        "login_fail": {"username": "root"},
        "login_success": {"username": "root"},
        "command": {
            "command": "uname -a",
            "output": "Linux web01 5.15.0 x86_64",
            "response_ms": 12,
            "answered_by": "engine",
            "techniques": ["T1082"],
        },
        "tripwire": {"tripwire_id": "aws-keys", "reasons": ["read fake creds"]},
        "classified": {"reasons": ["fast typing"]},
        "dossier": {"summary": "known scanner", "sources": [{"title": "x", "url": "https://example.com/x"}]},
        "story": {"story": "a goblin knocked on the gate"},
        "session_end": {"duration_s": 12.5, "command_count": 0},
    }
    ts = ts or datetime.now(timezone.utc)
    return {
        "event_id": str(uuid.uuid4()),
        "session_id": session_id,
        "type": type_,
        "timestamp": fmt_ts(ts),
        "source": source,
        "protocol": "ssh",
        "geo": {"lat": 52.37, "lon": 4.9, "country": country, "city": "Amsterdam"},
        "attacker": {
            "kind": kind,
            "confidence": 0.9,
            "reputation": reputation,
            "family": None,
            "threat": "high",
            "client": "SSH-2.0-Go",
            "ip_hash": "a" * 64,
        },
        "detail": detail if detail is not None else defaults[type_],
    }


class FakeStore:
    """in memory store with the same behaviour as PgStore, for api tests."""

    def __init__(self):
        self.events: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.fail = False
        self.started = False

    async def start(self):
        self.started = True

    async def close(self):
        pass

    async def ping(self):
        if self.fail:
            raise RuntimeError("db down")

    async def persist(self, event):
        if self.fail:
            raise RuntimeError("db down")
        if event["event_id"] in self.events:
            return False
        self.events[event["event_id"]] = copy.deepcopy(event)
        sid = event["session_id"]
        self.sessions[sid] = apply_event(self.sessions.get(sid), event)
        return True

    async def list_sessions(self, limit, source):
        rows = [r for r in self.sessions.values() if source is None or r["source"] == source]
        return sorted(rows, key=lambda r: r["started_at"], reverse=True)[:limit]

    async def get_session(self, session_id):
        return self.sessions.get(session_id)

    async def session_events(self, session_id):
        rows = [e for e in self.events.values() if e["session_id"] == session_id]
        return sorted(rows, key=lambda e: (e["timestamp"], e["event_id"]))

    async def stats(self) -> dict[str, Any]:
        wild = [r for r in self.sessions.values() if r["source"] == "wild"]
        now = datetime.now(timezone.utc)
        by_kind: dict[str, int] = {}
        by_rep: dict[str, int] = {}
        minutes: dict[tuple, int] = {}
        for r in wild:
            k, rep = r["attacker"]["kind"], r["attacker"]["reputation"]
            by_kind[k] = by_kind.get(k, 0) + 1
            by_rep[rep] = by_rep.get(rep, 0) + 1
            if r["started_at"] >= now - timedelta(hours=24) and k in ("bot", "human", "agent"):
                key = (r["started_at"].replace(second=0, microsecond=0), k)
                minutes[key] = minutes.get(key, 0) + 1
        return {
            "total": len(wild),
            "active": sum(
                1 for r in wild if r["status"] != "ended" and r["last_seen"] > now - timedelta(minutes=5)
            ),
            "countries": len({r["geo"]["country"] for r in wild if r["geo"]["country"] != "XX"}),
            "breaches": sum(1 for r in wild if r["breached"]),
            "by_kind": by_kind,
            "by_reputation": by_rep,
            "per_minute": [(t, k, n) for (t, k), n in sorted(minutes.items())],
        }

    async def cleanup(self):
        return 0


@pytest.fixture
def settings() -> Settings:
    return Settings(
        ingest_token=TOKEN,
        domain="example.com",
        ingest_rate_per_sec=1000,
        ingest_burst=1000,
        consumer_name="test",
        consumer_block_ms=50,
        stats_ttl=0,
    )


@pytest.fixture
def redis_server():
    return fakeredis.FakeServer()


@pytest.fixture
def redis(redis_server):
    return fakeredis.aioredis.FakeRedis(server=redis_server, decode_responses=True)


@pytest.fixture
def sync_redis(redis_server):
    # same fake server, usable from the test thread while the app runs in TestClient's loop
    return fakeredis.FakeRedis(server=redis_server, decode_responses=True)


@pytest.fixture
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture
def app(settings, redis, store):
    return create_app(settings, redis=redis, store=store)
