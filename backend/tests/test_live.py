import asyncio
import json
from dataclasses import replace

from fastapi.testclient import TestClient

from app.consumer import GROUP, STREAM, handle_entry, run_consumer
from app.live import PING, Hub
from app.main import create_app

from .conftest import FakeStore, load_example, make_event, validator


def push(sync_redis, event):
    sync_redis.xadd(STREAM, {"data": json.dumps(event)})


def receive_event(ws):
    # skip pings
    while True:
        msg = json.loads(ws.receive_text())
        if msg.get("type") != "ping":
            return msg


def test_events_are_persisted_and_broadcast_to_every_client(app, store, sync_redis):
    event = make_event("session_start", "s1")
    with TestClient(app) as client:
        with client.websocket_connect("/live") as a, client.websocket_connect("/live") as b:
            # wait until both are registered before pushing
            while len(app.state.hub.clients) < 2:
                pass
            push(sync_redis, event)
            got_a, got_b = receive_event(a), receive_event(b)
    assert got_a == got_b == event
    validator("event").validate(got_a)
    assert event["event_id"] in store.events
    assert sync_redis.xpending(STREAM, GROUP)["pending"] == 0


def test_invalid_event_is_never_broadcast(app, store, sync_redis):
    leak = load_example("invalid/event.src_ip_leak.json")
    good = make_event("session_start", "s2")
    with TestClient(app) as client:
        with client.websocket_connect("/live") as ws:
            while not app.state.hub.clients:
                pass
            push(sync_redis, leak)
            sync_redis.xadd(STREAM, {"data": "not json"})
            sync_redis.xadd(STREAM, {"other": "field"})
            push(sync_redis, good)
            assert receive_event(ws) == good
    assert list(store.events) == [good["event_id"]]
    assert sync_redis.xpending(STREAM, GROUP)["pending"] == 0


def test_ping_is_sent(settings, redis, store):
    app = create_app(replace(settings, ping_interval=0.05), redis=redis, store=store)
    with TestClient(app) as client:
        with client.websocket_connect("/live") as ws:
            assert ws.receive_text() == PING


class FakeWS:
    def __init__(self, slow=False):
        self.slow = slow
        self.sent: list[str] = []
        self.closed = asyncio.Event()
        self.close_code = None

    async def accept(self):
        pass

    async def send_text(self, text):
        if self.slow:
            await asyncio.sleep(3600)
        self.sent.append(text)

    async def receive(self):
        await self.closed.wait()
        return {"type": "websocket.disconnect"}

    async def close(self, code=1000):
        self.close_code = code
        self.closed.set()


async def wait_for(cond, timeout=2.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not cond():
        assert loop.time() < end, "condition not met in time"
        await asyncio.sleep(0.01)


async def test_slow_client_is_dropped_without_blocking_others():
    hub = Hub(ping_interval=60, send_timeout=60, queue_size=3)
    fast, slow = FakeWS(), FakeWS(slow=True)
    tasks = [asyncio.create_task(hub.serve(fast)), asyncio.create_task(hub.serve(slow))]
    await wait_for(lambda: len(hub.clients) == 2)

    for i in range(10):
        hub.broadcast(f"m{i}")  # sync: can't block on a socket
        await asyncio.sleep(0)

    await wait_for(lambda: len(fast.sent) == 10)
    assert fast.sent == [f"m{i}" for i in range(10)]
    await wait_for(lambda: len(hub.clients) == 1)
    await asyncio.wait_for(tasks[1], 2)
    assert slow.closed.is_set()

    await fast.close()
    await asyncio.wait_for(tasks[0], 2)
    assert not hub.clients


async def test_send_timeout_drops_client():
    hub = Hub(ping_interval=60, send_timeout=0.05, queue_size=100)
    slow = FakeWS(slow=True)
    task = asyncio.create_task(hub.serve(slow))
    await wait_for(lambda: len(hub.clients) == 1)
    hub.broadcast("hello")
    await asyncio.wait_for(task, 2)
    assert not hub.clients


async def test_persist_failure_leaves_entry_pending_and_still_broadcasts(redis):
    store, hub = FakeStore(), Hub()
    store.fail = True
    seen = []
    hub.broadcast = seen.append
    event = make_event("session_start", "s3")
    await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    await redis.xadd(STREAM, {"data": json.dumps(event)})
    resp = await redis.xreadgroup(GROUP, "c", {STREAM: ">"}, count=10)
    entry_id, fields = resp[0][1][0]
    await handle_entry(entry_id, fields, redis, store, hub)
    assert [json.loads(m) for m in seen] == [event]
    assert (await redis.xpending(STREAM, GROUP))["pending"] == 1


async def test_consumer_replays_pending_entries_after_restart(redis):
    event = make_event("session_start", "s4")
    await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    await redis.xadd(STREAM, {"data": json.dumps(event)})
    # a previous run read it but crashed before acking
    await redis.xreadgroup(GROUP, "c", {STREAM: ">"}, count=10)

    store, hub = FakeStore(), Hub()
    task = asyncio.create_task(run_consumer(redis, store, hub, "c", block_ms=20))
    await wait_for(lambda: event["event_id"] in store.events)
    for _ in range(100):
        if (await redis.xpending(STREAM, GROUP))["pending"] == 0:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    assert (await redis.xpending(STREAM, GROUP))["pending"] == 0
