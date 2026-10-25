"""integration tests against a real timescale database. set TEST_DATABASE_URL to run."""

import os
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from app.attackers import to_row
from app.sessions import to_summary
from app.stats import build_stats
from app.store import PgStore, run_migrations

from .conftest import make_event, validator

DSN = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


@pytest.fixture
async def store():
    conn = await asyncpg.connect(DSN)
    # start from an empty schema each time
    await conn.execute("drop table if exists events, sessions, schema_migrations cascade")
    await conn.close()
    s = PgStore(DSN)
    await s.start()
    yield s
    await s.close()


async def test_migrations_rerun_cleanly(store):
    async with store.pool.acquire() as conn:
        assert await run_migrations(conn) == []
        # files are idempotent on their own too
        await conn.execute("truncate schema_migrations")
        assert len(await run_migrations(conn)) == 2
        hyper = await conn.fetchval(
            "select count(*) from timescaledb_information.hypertables where hypertable_name = 'events'"
        )
        retention = await conn.fetchval(
            "select count(*) from timescaledb_information.jobs"
            " where proc_name = 'policy_retention' and hypertable_name = 'events'"
        )
    assert (hyper, retention) == (1, 1)


async def test_persist_is_idempotent(store):
    now = datetime.now(timezone.utc)
    fail = make_event("login_fail", "s1", now)
    assert await store.persist(make_event("session_start", "s1", now - timedelta(seconds=1)))
    assert await store.persist(fail)
    assert not await store.persist(fail)
    row = await store.get_session("s1")
    assert row["login_fails"] == 1
    assert row["status"] == "at_gate"
    validator("session_summary").validate(to_summary(row))


async def test_session_events_are_ordered_and_valid(store):
    now = datetime.now(timezone.utc)
    types = ["session_start", "login_fail", "login_success", "command", "session_end"]
    # insert out of order on purpose
    for i in (3, 0, 4, 1, 2):
        await store.persist(make_event(types[i], "s2", now + timedelta(seconds=i)))
    events = await store.session_events("s2")
    assert [e["type"] for e in events] == types
    v = validator("event")
    for e in events:
        v.validate(e)
    row = await store.get_session("s2")
    assert (row["status"], row["breached"], row["command_count"]) == ("ended", True, 1)


async def test_list_sessions(store):
    now = datetime.now(timezone.utc)
    for i, source in enumerate(["wild", "mock", "wild"]):
        await store.persist(make_event("session_start", f"l{i}", now + timedelta(seconds=i), source=source))
    assert [r["session_id"] for r in await store.list_sessions(50, None)] == ["l2", "l1", "l0"]
    assert [r["session_id"] for r in await store.list_sessions(1, None)] == ["l2"]
    assert [r["session_id"] for r in await store.list_sessions(50, "mock")] == ["l1"]


async def test_stats_only_count_wild(store):
    now = datetime.now(timezone.utc)
    # brain sends session_start as unknown, classification comes later
    await store.persist(make_event("session_start", "w1", now, kind="unknown"))
    await store.persist(make_event("classified", "w1", now + timedelta(seconds=1), kind="bot"))
    await store.persist(make_event("login_success", "w1", now + timedelta(seconds=2), kind="bot"))
    await store.persist(make_event("session_start", "w2", now, kind="unknown", country="BR"))
    await store.persist(make_event("session_start", "w3", now, kind="human", country="XX"))
    await store.persist(make_event("session_end", "w3", now + timedelta(seconds=1), kind="human", country="XX"))
    for source in ("mock", "guest", "team"):
        await store.persist(make_event("session_start", f"{source}-1", now, source=source, kind="agent", country="JP"))
        await store.persist(make_event("login_success", f"{source}-1", now, source=source, kind="agent"))

    stats = build_stats(await store.stats())
    validator("stats").validate(stats)
    assert stats["total_sessions"] == 3
    assert stats["active_now"] == 2
    assert stats["countries"] == 2
    assert stats["breaches"] == 1
    assert stats["by_kind"] == {"bot": 1, "human": 1, "agent": 0, "unknown": 1}
    assert stats["by_reputation"] == {"harmless": 0, "unknown": 0, "malicious": 3}
    totals = {k: sum(b[k] for b in stats["per_minute"]) for k in ("bot", "human", "agent")}
    # w1 counted by its current kind, w2 still unknown so skipped, non wild ignored
    assert totals == {"bot": 1, "human": 1, "agent": 0}


async def test_per_minute_window_is_24h(store):
    old = datetime.now(timezone.utc) - timedelta(hours=30)
    await store.persist(make_event("session_start", "old", old, kind="bot"))
    stats = build_stats(await store.stats())
    assert stats["per_minute"] == []
    assert stats["total_sessions"] == 1


async def test_cleanup_drops_sessions_past_retention(store):
    now = datetime.now(timezone.utc)
    await store.persist(make_event("session_start", "ancient", now - timedelta(days=8)))
    await store.persist(make_event("session_start", "fresh", now))
    assert await store.cleanup() == 1
    assert await store.get_session("ancient") is None
    assert await store.get_session("fresh") is not None


async def test_list_attackers(store):
    now = datetime.now(timezone.utc)
    h1, h2 = "1" * 64, "2" * 64
    for i in range(52):
        await store.persist(make_event("session_start", f"a{i:02d}", now + timedelta(seconds=i), ip_hash=h1))
    await store.persist(make_event("classified", "a51", now + timedelta(seconds=60), ip_hash=h1, kind="human"))
    await store.persist(make_event("session_start", "b0", now + timedelta(seconds=30), ip_hash=h2, source="mock"))
    await store.persist(make_event("session_start", "nohash", now + timedelta(seconds=90), ip_hash=None))

    rows = [to_row(r) for r in await store.list_attackers(100, None)]
    v = validator("attacker_summary")
    for r in rows:
        v.validate(r)
    assert [r["ip_hash"] for r in rows] == [h1, h2]
    a = rows[0]
    assert a["visits"] == 52 and a["latest_session_id"] == "a51"
    assert len(a["session_ids"]) == 50 and a["session_ids"][0] == "a51" and a["session_ids"][-1] == "a02"
    assert a["attacker"]["kind"] == "human"
    assert a["max_threat"] == "high"
    assert [r["ip_hash"] for r in await store.list_attackers(100, "mock")] == [h2]
    assert len(await store.list_attackers(1, None)) == 1


async def test_list_attackers_kind_from_newest_classified_and_max_threat(store):
    now = datetime.now(timezone.utc)
    h = "4" * 64
    t = lambda s: now - timedelta(seconds=s)  # noqa: E731
    await store.persist(make_event("session_start", "b-1", t(900), ip_hash=h, kind="unknown", threat="low"))
    await store.persist(make_event("classified", "b-1", t(899), ip_hash=h, kind="bot", threat="critical"))
    await store.persist(make_event("session_start", "b-2", t(600), ip_hash=h, kind="unknown", threat="low"))
    await store.persist(make_event("classified", "b-2", t(599), ip_hash=h, kind="bot", confidence=0.75,
                                   threat="med"))
    await store.persist(make_event("session_start", "b-3", t(30), ip_hash=h, kind="unknown", threat="low",
                                   confidence=0.0))
    await store.persist(make_event("session_start", "u-1", t(20), ip_hash="5" * 64, kind="unknown",
                                   threat="med", confidence=0.0))

    rows = [to_row(r) for r in await store.list_attackers(100, None)]
    v = validator("attacker_summary")
    for r in rows:
        v.validate(r)
    unknown, bot = rows
    assert bot["latest_session_id"] == "b-3"
    assert bot["attacker"]["kind"] == "bot" and bot["attacker"]["confidence"] == 0.75
    assert bot["attacker"]["threat"] == "low" and bot["max_threat"] == "critical"
    assert unknown["attacker"]["kind"] == "unknown" and unknown["max_threat"] == "med"
