import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.sessions import fmt_ts

from .conftest import load_example, make_event, validator


def seed(store, events):
    async def run():
        for e in events:
            await store.persist(e)

    asyncio.run(run())


def no_raw_ips(text: str):
    assert "src_ip" not in text
    assert "203.0.113" not in text


@pytest.fixture
def seeded(store):
    now = datetime.now(timezone.utc)
    events = [
        make_event("session_start", "wild-1", now - timedelta(seconds=30), kind="unknown"),
        make_event("classified", "wild-1", now - timedelta(seconds=29), kind="bot"),
        make_event("login_fail", "wild-1", now - timedelta(seconds=28)),
        make_event("login_success", "wild-1", now - timedelta(seconds=27)),
        make_event("command", "wild-1", now - timedelta(seconds=26)),
        make_event("session_start", "wild-2", now - timedelta(seconds=20), kind="human", country="BR"),
        make_event("session_end", "wild-2", now - timedelta(seconds=10), kind="human", country="BR"),
        make_event("session_start", "wild-3", now - timedelta(seconds=5), kind="unknown", country="XX"),
        make_event("session_start", "mock-1", now, source="mock", kind="agent", country="JP"),
        make_event("session_start", "guest-1", now, source="guest", kind="human", country="US"),
    ]
    # contract examples, moved two days back so they sit outside the 24h and active windows
    old = fmt_ts(now - timedelta(days=2))
    for n in ("session_start", "login_fail", "command", "story"):
        example = load_example(f"valid/event.{n}.json")
        example["timestamp"] = old
        events.append(example)
    seed(store, events)
    return events


def test_sessions_newest_first_and_valid(app, seeded):
    with TestClient(app) as client:
        resp = client.get("/sessions")
    assert resp.status_code == 200
    body = resp.json()
    v = validator("session_summary")
    for s in body:
        v.validate(s)
    started = [s["started_at"] for s in body]
    assert started == sorted(started, reverse=True)
    assert {s["session_id"] for s in body} >= {"wild-1", "mock-1", "guest-1"}
    no_raw_ips(resp.text)


def test_sessions_limit_and_source(app, seeded):
    with TestClient(app) as client:
        assert len(client.get("/sessions?limit=2").json()) == 2
        assert [s["session_id"] for s in client.get("/sessions?source=mock").json()] == ["mock-1"]
        assert client.get("/sessions?limit=0").status_code == 422
        assert client.get("/sessions?limit=201").status_code == 422
        assert client.get("/sessions?source=evil").status_code == 422


def test_session_detail_has_ordered_events(app, seeded):
    with TestClient(app) as client:
        resp = client.get("/sessions/wild-1")
    assert resp.status_code == 200
    body = resp.json()
    validator("session_summary").validate(body["session"])
    assert body["session"]["status"] == "inside"
    assert body["session"]["login_fails"] == 1
    assert body["session"]["command_count"] == 1
    ev = validator("event")
    for e in body["events"]:
        ev.validate(e)
    assert [e["type"] for e in body["events"]] == [
        "session_start",
        "classified",
        "login_fail",
        "login_success",
        "command",
    ]
    no_raw_ips(resp.text)


def test_session_detail_404(app):
    with TestClient(app) as client:
        assert client.get("/sessions/nope").status_code == 404


def test_stats_count_only_wild(app, seeded):
    with TestClient(app) as client:
        resp = client.get("/stats")
    assert resp.status_code == 200
    stats = resp.json()
    validator("stats").validate(stats)
    # wild-1, wild-2, wild-3 and the contract example session
    assert stats["total_sessions"] == 4
    assert stats["breaches"] == 1
    assert stats["countries"] == 2  # NL and BR; XX does not count, mock JP and guest US are ignored
    assert stats["active_now"] == 2  # wild-1 and wild-3; example session is old, wild-2 ended
    assert stats["by_kind"] == {"bot": 2, "human": 1, "agent": 0, "unknown": 1}
    total_per_minute = sum(b["bot"] + b["human"] + b["agent"] for b in stats["per_minute"])
    # unknown wild-3 skipped, example session is older than 24h
    assert total_per_minute == 2
    no_raw_ips(resp.text)


def test_health(app, store):
    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok", "redis": "ok", "db": "ok"}
        store.fail = True
        resp = client.get("/health")
    assert resp.status_code == 503
    assert resp.json()["db"] == "down"


def test_cors(app):
    with TestClient(app) as client:
        for origin in ("https://example.com", "https://hx-world-git-main.vercel.app", "http://localhost:3000"):
            resp = client.get("/health", headers={"Origin": origin})
            assert resp.headers.get("access-control-allow-origin") == origin
        resp = client.get("/health", headers={"Origin": "https://evil.com"})
        assert "access-control-allow-origin" not in resp.headers


H1, H2, H3 = "1" * 64, "2" * 64, "3" * 64


@pytest.fixture
def visitors(store):
    now = datetime.now(timezone.utc)
    t = lambda s: now - timedelta(seconds=s)  # noqa: E731
    seed(store, [
        # H1: three wild visits, the newest one classified later
        make_event("session_start", "h1-old", t(300), ip_hash=H1, kind="unknown", country="CH"),
        make_event("session_end", "h1-old", t(299), ip_hash=H1, kind="bot", country="CH"),
        make_event("session_start", "h1-mid", t(200), ip_hash=H1, kind="unknown"),
        make_event("session_start", "h1-new", t(100), ip_hash=H1, kind="unknown", country="DE"),
        make_event("classified", "h1-new", t(50), ip_hash=H1, kind="human", reputation="unknown", country="DE"),
        # H2: one visit, the most recent activity overall
        make_event("session_start", "h2-only", t(10), ip_hash=H2, kind="agent", country="BR"),
        # H3: mock only, older
        make_event("session_start", "h3-mock", t(400), ip_hash=H3, source="mock", kind="bot", country="JP"),
        # no ip hash, never listed
        make_event("session_start", "nohash", t(5), ip_hash=None, kind="bot"),
    ])


def test_attackers_grouped_and_newest_first(app, visitors):
    with TestClient(app) as client:
        resp = client.get("/attackers")
    assert resp.status_code == 200
    body = resp.json()
    v = validator("attacker_summary")
    for row in body:
        v.validate(row)
    assert [a["ip_hash"] for a in body] == [H2, H1, H3]
    h1 = body[1]
    assert h1["visits"] == 3
    assert h1["session_ids"] == ["h1-new", "h1-mid", "h1-old"]
    assert h1["latest_session_id"] == "h1-new"
    assert h1["first_seen"] < h1["last_seen"]
    # profile and place come from the most recent session
    assert h1["geo"]["country"] == "DE"
    assert h1["attacker"] == {"kind": "human", "confidence": 0.9, "reputation": "unknown",
                              "family": None, "threat": "high"}


def test_attackers_skip_null_ip_hash_and_leak_nothing(app, visitors):
    with TestClient(app) as client:
        resp = client.get("/attackers")
    ids = {sid for a in resp.json() for sid in a["session_ids"]}
    assert "nohash" not in ids
    no_raw_ips(resp.text)
    assert "client" not in resp.text


def test_attackers_limit_and_source(app, visitors):
    with TestClient(app) as client:
        assert [a["ip_hash"] for a in client.get("/attackers?limit=1").json()] == [H2]
        assert [a["ip_hash"] for a in client.get("/attackers?source=mock").json()] == [H3]
        wild = client.get("/attackers?source=wild").json()
        assert [a["ip_hash"] for a in wild] == [H2, H1]
        assert client.get("/attackers?limit=500").status_code == 200
        assert client.get("/attackers?limit=0").status_code == 422
        assert client.get("/attackers?limit=501").status_code == 422
        assert client.get("/attackers?source=evil").status_code == 422


def test_attackers_cap_session_ids_at_50(app, store):
    now = datetime.now(timezone.utc)
    seed(store, [make_event("session_start", f"s{i:02d}", now + timedelta(seconds=i), ip_hash=H1)
                 for i in range(55)])
    with TestClient(app) as client:
        row = client.get("/attackers").json()[0]
    validator("attacker_summary").validate(row)
    assert row["visits"] == 55
    assert len(row["session_ids"]) == 50
    assert row["session_ids"][0] == "s54" and row["session_ids"][-1] == "s05"
