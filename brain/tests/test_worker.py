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
