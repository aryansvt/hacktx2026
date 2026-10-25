import asyncio
import json

import fakeredis
import pytest
from redis.exceptions import TimeoutError as RedisTimeoutError

import brain.worker as w

from brain.worker import DEAD, EVENTS, GROUP, RAW, Brain

from fakes import SETTINGS, FakeGeo, event_validator, load_fixture

VALIDATOR = event_validator()


async def push(r, events):
    for e in events:
        await r.xadd(RAW, {"data": json.dumps(e)})


async def read_events(r):
    return [json.loads(f[b"data"]) for _id, f in await r.xrange(EVENTS)]


async def test_end_to_end_stream():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    await brain.ensure_group()
    await push(r, load_fixture("agent"))
    while await brain.step(count=5):
        pass
    events = await read_events(r)
    raws = load_fixture("agent")
    assert [e["event_id"] for e in events if e["type"] not in ("classified",)] == [x["event_id"] for x in raws]
    assert any(e["type"] == "classified" and e["attacker"]["kind"] == "agent" for e in events)
    for ev in events:
        VALIDATOR.validate(ev)
    pending = await r.xpending(RAW, GROUP)
    assert pending["pending"] == 0


async def test_restart_reprocesses_pending():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    await brain.ensure_group()
    raws = load_fixture("bot")
    await push(r, raws[:3])
    # read without processing, like a crash right after xreadgroup
    await r.xreadgroup(GROUP, SETTINGS.consumer, {RAW: ">"}, count=3)
    assert (await r.xpending(RAW, GROUP))["pending"] == 3

    restarted = Brain(r, SETTINGS, FakeGeo())
    await restarted.ensure_group()  # BUSYGROUP is fine
    assert await restarted.drain_pending() == 3
    assert (await r.xpending(RAW, GROUP))["pending"] == 0
    assert len(await read_events(r)) == 3


async def test_duplicate_event_is_skipped():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    await brain.ensure_group()
    raws = load_fixture("human")
    await push(r, raws[:3] + raws[2:3])
    while await brain.step():
        pass
    events = await read_events(r)
    assert [e["event_id"] for e in events].count(raws[2]["event_id"]) == 1
    session = await brain.store.get(raws[0]["session_id"])
    assert len(session.logins) == 2


async def test_bad_messages_go_to_dead_letter():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    await brain.ensure_group()
    await r.xadd(RAW, {"data": "not json"})
    bad = dict(load_fixture("bot")[1])
    bad["detail"] = {"username": "root", "success": False, "password": "x"}
    await r.xadd(RAW, {"data": json.dumps(bad)})
    while await brain.step():
        pass
    assert await r.xlen(DEAD) == 2
    assert await r.xlen(EVENTS) == 0
    assert (await r.xpending(RAW, GROUP))["pending"] == 0


async def test_session_state_persists_across_brains():
    r = fakeredis.FakeAsyncRedis()
    raws = load_fixture("bot")
    a = Brain(r, SETTINGS, FakeGeo())
    for e in raws[:5]:
        await a.handle(e)
    b = Brain(r, SETTINGS, FakeGeo())
    out = []
    for e in raws[5:]:
        out += await b.handle(e)
    assert out[-1]["attacker"]["kind"] == "bot"
    s = await b.store.get(raws[0]["session_id"])
    assert s.login_fails == 4 and s.command_count == 5 and s.status == "ended"
    assert s.downloads == ["bins.sh"]


async def test_run_survives_redis_blips(monkeypatch):
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    calls = {"n": 0}

    async def flaky(start=">", count=50, block_ms=None):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RedisTimeoutError("blip")
        if calls["n"] >= 4:
            raise asyncio.CancelledError
        return 0

    async def no_sleep(_s):
        return None

    monkeypatch.setattr(brain, "step", flaky)
    monkeypatch.setattr(w.asyncio, "sleep", no_sleep)
    with pytest.raises(asyncio.CancelledError):
        await brain.run()
    assert calls["n"] == 4


async def test_quick_scan_classified_before_session_end():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    raws = load_fixture("scanner")
    for e in raws[:-1]:
        out = await brain.handle(e)
        assert all(ev["attacker"]["kind"] == "unknown" for ev in out)
    out = await brain.handle(raws[-1])
    assert [ev["type"] for ev in out] == ["classified", "session_end"]
    assert out[0]["attacker"]["kind"] == "bot" and out[0]["attacker"]["confidence"] == 0.7
    assert "scanner SSH client (Go)" in out[0]["detail"]["reasons"]
    for ev in out:
        VALIDATOR.validate(ev)
    s = await brain.store.get(raws[0]["session_id"])
    assert s.kind == "bot"


async def test_dropper_sequence_goes_critical():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    raws = load_fixture("bot")
    start, login, cmd = raws[0], raws[5], raws[6]
    lines = [
        "cd /tmp",
        "echo -ne '\x7f\x45\x4c\x46\x02\x01' > .d",
        "echo -ne '\x00\x00\x00\x00' >> .d",
        "chmod +x .d",
        "./.d",
    ]
    await brain.handle(start)
    await brain.handle(login)
    threats = []
    for i, line in enumerate(lines):
        ev = dict(cmd, event_id=f"00000000-0000-4000-8000-{i:012d}",
                  detail=dict(cmd["detail"], input=line, output=""))
        out = await brain.handle(ev)
        threats.append(out[0]["attacker"]["threat"])
    assert threats[:3] == ["med", "med", "med"]
    assert threats[3:] == ["critical", "critical"]
    s = await brain.store.get(start["session_id"])
    assert s.written == [".d"] and s.downloads == []


# ---- repeat visitors ----

def _visit(sid, start, client="SSH-2.0-OpenSSH_9.6p1", source="wild", ip="192.0.2.40", end_after=20.0):
    """one login-only session as raw events, start is epoch seconds."""
    from brain.session import fmt_ts
    base = {"session_id": sid, "source": source, "protocol": "ssh", "src_ip": ip}
    return [
        {**base, "event_id": w.derived_id(sid, "start"), "type": "session_start", "timestamp": fmt_ts(start),
         "detail": {"client": client}},
        {**base, "event_id": w.derived_id(sid, "login"), "type": "login_fail", "timestamp": fmt_ts(start + 1),
         "detail": {"username": "root", "success": False}},
        {**base, "event_id": w.derived_id(sid, "end"), "type": "session_end",
         "timestamp": fmt_ts(start + end_after), "detail": {"duration_s": end_after, "command_count": 0}},
    ]


T0 = 1_792_000_000.0


async def _run(brain, raws):
    out = []
    for e in raws:
        out += await brain.handle(e)
    return out


async def test_tenth_visit_in_an_hour_is_a_bot():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    for i in range(9):
        out = await _run(brain, _visit(f"ssh-v{i}", T0 + i * 300))
        assert all(ev["attacker"]["kind"] == "unknown" for ev in out)
    out = await _run(brain, _visit("ssh-v9", T0 + 9 * 300))
    cls = [ev for ev in out if ev["type"] == "classified"]
    assert len(cls) == 1 and out[-1]["type"] == "session_end"
    assert cls[0]["attacker"]["kind"] == "bot" and cls[0]["attacker"]["confidence"] == 0.75
    assert cls[0]["detail"]["reasons"][0] == "connected 10 times in the last hour"
    for ev in out:
        VALIDATOR.validate(ev)
    # tracked by ip_hash only, never the raw ip
    keys = [k.decode() for k in await r.keys("brain:visits:*")]
    assert keys == [f"brain:visits:{cls[0]['attacker']['ip_hash']}"]


async def test_visits_older_than_an_hour_drop_out():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    for i in range(9):
        await _run(brain, _visit(f"ssh-old{i}", T0 + i))
    out = await _run(brain, _visit("ssh-late", T0 + 3700))
    assert all(ev["attacker"]["kind"] == "unknown" for ev in out)
    s = await brain.store.get("ssh-late")
    assert s.recent_sessions == 1


async def test_session_end_counts_visits_that_arrived_meanwhile():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    long = _visit("ssh-long", T0, end_after=600)
    await _run(brain, long[:2])
    for i in range(9):
        await _run(brain, _visit(f"ssh-v{i}", T0 + 10 + i))
    out = await brain.handle(long[2])
    assert out[0]["type"] == "classified" and out[0]["attacker"]["kind"] == "bot"


async def test_guest_and_team_visits_are_not_counted():
    r = fakeredis.FakeAsyncRedis()
    brain = Brain(r, SETTINGS, FakeGeo())
    for i in range(12):
        out = await _run(brain, _visit(f"ssh-g{i}", T0 + i, source="guest"))
        assert all(ev["attacker"]["kind"] == "unknown" for ev in out)
    assert await r.keys("brain:visits:*") == []
