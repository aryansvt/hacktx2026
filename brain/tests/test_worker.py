import json

import fakeredis

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
