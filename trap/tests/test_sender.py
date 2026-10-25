import json

import httpx
import pytest

from honeypot import sender as sender_mod
from honeypot.config import Settings
from honeypot.events import JsonlSink, SessionEvents
from honeypot.sender import BACKOFF_MAX, FAILED, IDLE, SENT, OffTarget, Sender

pytestmark = pytest.mark.usefixtures("no_network_async")

URL = "https://api.example.test"


class Core:
    """fake core. reply(events) returns a response or raises."""

    def __init__(self, reply=None):
        self.reply = reply or (lambda events: httpx.Response(202, json={"accepted": len(events)}))
        self.requests: list[httpx.Request] = []
        self.accepted: list = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        events = json.loads(request.content)
        resp = self.reply(events)
        if 200 <= resp.status_code < 300:
            self.accepted += events
        return resp


def make(tmp_path, core, **kw) -> Sender:
    s = Settings(state_dir=tmp_path, core_url=kw.pop("core_url", URL), ingest_token=kw.pop("token", "tok"))
    return Sender(s, transport=httpx.MockTransport(core), **kw)


def spool(tmp_path, *events, raw: str = "") -> None:
    with (tmp_path / "spool.jsonl").open("a", encoding="utf-8", newline="\n") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
        f.write(raw)


def cursor(tmp_path) -> int:
    return int((tmp_path / "spool.cursor").read_text())


def dead(tmp_path) -> list[dict]:
    path = tmp_path / "dead_letter.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def down(events):
    raise httpx.ConnectError("refused")


async def test_sends_in_batches_of_100(tmp_path):
    core = Core()
    spool(tmp_path, *({"n": i} for i in range(250)))
    s = make(tmp_path, core)
    assert [await s.step() for _ in range(4)] == [SENT, SENT, SENT, IDLE]
    assert [len(json.loads(r.content)) for r in core.requests] == [100, 100, 50]
    req = core.requests[0]
    assert str(req.url) == URL + "/ingest"
    assert req.method == "POST"
    assert req.headers["authorization"] == "Bearer tok"
    assert req.headers["content-type"] == "application/json"
    assert core.accepted == [{"n": i} for i in range(250)]
    assert cursor(tmp_path) == (tmp_path / "spool.jsonl").stat().st_size
    await s.close()


async def test_cursor_survives_restart(tmp_path):
    core = Core()
    spool(tmp_path, {"n": 1}, {"n": 2})
    s = make(tmp_path, core)
    await s.step()
    await s.close()
    spool(tmp_path, {"n": 3})
    s2 = make(tmp_path, core)
    assert await s2.step() == SENT
    assert core.accepted == [{"n": 1}, {"n": 2}, {"n": 3}]
    await s2.close()


async def test_spool_from_session_events(tmp_path):
    core = Core()
    ev = SessionEvents(JsonlSink(tmp_path / "spool.jsonl"), "198.51.100.4")
    ev.session_start("SSH-2.0-Go")
    ev.login_success("root")
    ev.resolve("wild")
    s = make(tmp_path, core)
    await s.step()
    assert [e["type"] for e in core.accepted] == ["session_start", "login_success"]
    await s.close()


@pytest.mark.parametrize(
    "reply",
    [down, lambda e: httpx.Response(500), lambda e: httpx.Response(401), lambda e: httpx.Response(503)],
)
async def test_core_down_keeps_events(tmp_path, reply):
    core = Core(reply)
    spool(tmp_path, {"n": 1}, {"n": 2})
    s = make(tmp_path, core)
    assert await s.step() == FAILED
    assert await s.step() == FAILED
    assert not (tmp_path / "spool.cursor").exists()
    assert dead(tmp_path) == []
    core.reply = Core().reply
    assert await s.step() == SENT
    assert core.accepted == [{"n": 1}, {"n": 2}]
    await s.close()


async def test_timeout_keeps_events(tmp_path):
    def slow(events):
        raise httpx.ReadTimeout("slow")

    spool(tmp_path, {"n": 1})
    s = make(tmp_path, Core(slow))
    assert await s.step() == FAILED
    assert s.cursor == 0
    await s.close()


def bad_is_invalid(events):
    if any(e.get("bad") for e in events):
        return httpx.Response(422, json={"detail": {"message": "invalid raw events"}})
    return httpx.Response(202, json={"accepted": len(events)})


async def test_422_splits_and_dead_letters_the_bad_one(tmp_path):
    core = Core(bad_is_invalid)
    spool(tmp_path, {"n": 1}, {"n": 2, "bad": True}, {"n": 3})
    s = make(tmp_path, core)
    assert await s.step() == SENT
    assert core.accepted == [{"n": 1}, {"n": 3}]
    # one batch, then one request per event
    assert len(core.requests) == 4
    [rec] = dead(tmp_path)
    assert rec["event"] == {"n": 2, "bad": True}
    assert rec["status"] == 422
    assert "invalid raw events" in rec["reason"]
    assert rec["rejected_at"].endswith("Z")
    assert cursor(tmp_path) == (tmp_path / "spool.jsonl").stat().st_size
    # later events still flow
    spool(tmp_path, {"n": 4})
    assert await s.step() == SENT
    assert core.accepted[-1] == {"n": 4}
    assert len(dead(tmp_path)) == 1
    await s.close()


async def test_single_rejected_event_is_not_resent(tmp_path):
    core = Core(lambda e: httpx.Response(413))
    spool(tmp_path, {"bad": True})
    s = make(tmp_path, core)
    assert await s.step() == SENT
    assert len(core.requests) == 1
    assert dead(tmp_path)[0]["status"] == 413
    assert await s.step() == IDLE
    await s.close()


async def test_core_goes_down_mid_split(tmp_path):
    calls = {"n": 0}

    def reply(events):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(422)
        if calls["n"] == 2:
            return httpx.Response(202)
        raise httpx.ConnectError("gone")

    core = Core(reply)
    spool(tmp_path, {"n": 1}, {"n": 2}, {"n": 3})
    first_end = len(json.dumps({"n": 1})) + 1
    s = make(tmp_path, core)
    assert await s.step() == FAILED
    assert cursor(tmp_path) == first_end
    assert dead(tmp_path) == []
    core.reply = Core().reply
    assert await s.step() == SENT
    assert core.accepted == [{"n": 1}, {"n": 2}, {"n": 3}]
    await s.close()


async def test_half_written_line_waits(tmp_path):
    core = Core()
    spool(tmp_path, {"n": 1}, raw='{"n": 2')
    s = make(tmp_path, core)
    assert await s.step() == SENT
    assert await s.step() == IDLE
    assert core.accepted == [{"n": 1}]
    spool(tmp_path, raw="}\n")
    assert await s.step() == SENT
    assert core.accepted == [{"n": 1}, {"n": 2}]
    await s.close()


async def test_bad_json_and_blank_lines(tmp_path):
    core = Core()
    spool(tmp_path, {"n": 1}, raw="not json\n\n")
    spool(tmp_path, {"n": 2})
    s = make(tmp_path, core)
    while await s.step() != IDLE:
        pass
    assert core.accepted == [{"n": 1}, {"n": 2}]
    [rec] = dead(tmp_path)
    assert rec == {"rejected_at": rec["rejected_at"], "status": None, "reason": "not json", "event": "not json"}
    assert cursor(tmp_path) == (tmp_path / "spool.jsonl").stat().st_size
    await s.close()


async def test_disabled_without_url_or_token(tmp_path):
    assert not make(tmp_path, Core(), core_url="").enabled
    assert not make(tmp_path, Core(), token="").enabled
    assert not make(tmp_path, Core(), core_url="ftp://api.example.test").enabled
    s = make(tmp_path, Core(), core_url="http://localhost:8000")
    assert s.enabled
    await s.close()


async def test_guard_blocks_other_hosts(tmp_path):
    core = Core()
    s = make(tmp_path, core)
    with pytest.raises(OffTarget):
        await s.client.post("https://evil.example/ingest", json=[])
    with pytest.raises(OffTarget):
        await s.client.post("http://api.example.test/ingest", json=[])
    assert core.requests == []
    await s.close()


async def test_redirect_is_not_followed(tmp_path):
    core = Core(lambda e: httpx.Response(307, headers={"location": "https://elsewhere.example/ingest"}))
    spool(tmp_path, {"n": 1})
    s = make(tmp_path, core)
    assert await s.step() == FAILED
    assert len(core.requests) == 1
    assert s.cursor == 0
    await s.close()


class Stop(Exception):
    pass


def recorder(limit):
    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= limit:
            raise Stop

    return sleeps, sleep


async def test_backoff_doubles_and_caps(tmp_path):
    sleeps, sleep = recorder(9)
    spool(tmp_path, {"n": 1})
    s = make(tmp_path, Core(down), sleep=sleep)
    with pytest.raises(Stop):
        await s.run()
    caps = [1, 2, 4, 8, 16, 32, 60, 60, 60]
    assert all(0.75 * c <= got <= c for got, c in zip(sleeps, caps))
    assert max(sleeps) <= BACKOFF_MAX
    await s.close()


async def test_backoff_resets_after_success(tmp_path):
    calls = {"n": 0}

    def flaky(events):
        calls["n"] += 1
        if calls["n"] in (1, 2, 4):
            raise httpx.ConnectError("refused")
        return httpx.Response(202)

    sleeps, sleep = recorder(4)
    spool(tmp_path, {"n": 1})
    s = make(tmp_path, Core(flaky), sleep=sleep)

    # fail, fail, send, then idle; then the next event fails once
    async def sleep_then_spool(seconds):
        if len(sleeps) == 2:
            spool(tmp_path, {"n": 2})
        await sleep(seconds)

    s.sleep = sleep_then_spool
    with pytest.raises(Stop):
        await s.run()
    assert sleeps[0] <= 1 and 1.5 <= sleeps[1] <= 2
    assert sleeps[2] == sender_mod.IDLE_SLEEP
    assert sleeps[3] <= 1
    await s.close()


async def test_429_waits_retry_after(tmp_path):
    sleeps, sleep = recorder(2)
    core = Core(lambda e: httpx.Response(429, headers={"retry-after": "7"}))
    spool(tmp_path, {"n": 1})
    s = make(tmp_path, core, sleep=sleep)
    with pytest.raises(Stop):
        await s.run()
    assert sleeps == [7.0, 7.0]
    assert s.cursor == 0
    await s.close()


async def test_crashing_step_does_not_kill_the_loop(tmp_path, monkeypatch):
    sleeps, sleep = recorder(2)
    s = make(tmp_path, Core(), sleep=sleep)

    def boom():
        raise OSError("disk")

    monkeypatch.setattr(s, "_read_batch", boom)
    with pytest.raises(Stop):
        await s.run()
    assert len(sleeps) == 2
    await s.close()


async def test_compacts_spool_once_drained(tmp_path):
    core = Core()
    spool(tmp_path, *({"n": i} for i in range(10)))
    s = make(tmp_path, core)
    s.compact_bytes = 50
    assert await s.step() == SENT
    assert await s.step() == IDLE
    assert (tmp_path / "spool.jsonl").stat().st_size == 0
    assert cursor(tmp_path) == 0
    spool(tmp_path, {"n": 10})
    assert await s.step() == SENT
    assert core.accepted[-1] == {"n": 10}
    await s.close()


async def test_cursor_past_end_resets(tmp_path):
    spool(tmp_path, {"n": 1})
    (tmp_path / "spool.cursor").write_text("99999")
    core = Core()
    s = make(tmp_path, core)
    assert s.cursor == 0
    assert await s.step() == SENT
    assert core.accepted == [{"n": 1}]
    await s.close()


async def test_config_reads_core_settings():
    s = Settings.from_env({"CORE_URL": " https://api.example.test/ ", "INGEST_TOKEN": "abc", "TRAP_STATE_DIR": "/st"})
    assert s.core_url == "https://api.example.test"
    assert s.ingest_token == "abc"
    assert s.cursor_path.name == "spool.cursor"
    assert s.dead_letter_path.name == "dead_letter.jsonl"
    assert Settings.from_env({}).core_url == ""
