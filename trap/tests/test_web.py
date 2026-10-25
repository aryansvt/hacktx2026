"""the fake website through httpx's asgi transport, plus one real uvicorn run on localhost."""

import asyncio
from dataclasses import replace

import httpx
import pytest

from hacktx_contracts import parse_raw_event

from honeypot.config import Settings
from honeypot.events import MemorySink
from honeypot.tripwires import find_canaries
from honeypot.web import MAX_BODY, SERVER, HttpSessions, WebServer, build_app

IP = "203.0.113.7"
SECRET_PW = "web-Pw-55kq"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def site(base):
    sink, clock = MemorySink(), Clock()
    sessions = HttpSessions(sink, frozenset({"198.51.100.9"}), find_canaries(base), clock)
    app = build_app(sessions, base)

    def client(ip=IP):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app, client=(ip, 51515)), base_url="http://qf-web-01")

    client.sink, client.clock, client.sessions = sink, clock, sessions
    return client


def kinds(sink):
    return [e["type"] for e in sink.events]


def trips(sink):
    return [e["detail"] for e in sink.events if e["type"] == "tripwire"]


async def test_homepage_matches_the_fs_and_looks_like_nginx(site, base):
    async with site() as c:
        r = await c.get("/")
    assert r.status_code == 200 and r.headers["server"] == SERVER
    assert r.text == base.nodes["/var/www/html/index.html"].content
    assert "Note for AI agents" in r.text
    # seeing the page isn't a tripwire, doing what it asks is
    assert trips(site.sink) == []


async def test_robots_static_and_404(site, base):
    async with site() as c:
        robots = await c.get("/robots.txt")
        css = await c.get("/static/site.css")
        missing = await c.get("/wp-login.php")
        post = await c.post("/xmlrpc.php", content=b"<x/>")
    assert robots.text == base.nodes["/var/www/html/robots.txt"].content and "Disallow: /admin" in robots.text
    assert css.headers["content-type"] == "text/css" and robots.headers["content-type"] == "text/plain"
    assert missing.status_code == 404 and "<center>nginx/1.18.0 (Ubuntu)</center>" in missing.text
    assert post.status_code == 404
    cmds = [e["detail"] for e in site.sink.events if e["type"] == "command"]
    assert [(c["input"], c["output"]) for c in cmds] == [
        ("GET /robots.txt", "200 OK"),
        ("GET /static/site.css", "200 OK"),
        ("GET /wp-login.php", "404 Not Found"),
        ("POST /xmlrpc.php", "404 Not Found"),
    ]


async def test_admin_keeps_only_the_username(site):
    async with site() as c:
        form = await c.get("/admin")
        r = await c.post("/admin", data={"username": "admin<b>", "password": SECRET_PW})
    assert 'name="password"' in form.text
    assert r.status_code == 200 and "Invalid username or password." in r.text
    assert "admin&lt;b&gt;" in r.text
    fails = [e["detail"] for e in site.sink.events if e["type"] == "login_fail"]
    assert fails == [{"username": "admin<b>", "success": False}]
    assert SECRET_PW not in repr(site.sink.events)


async def test_canary_password_at_admin_trips_without_storing_it(site):
    async with site() as c:
        await c.post("/admin", data={"username": "qf_app", "password": "FAKE-CANARY-7f3a91c2"})
    assert trips(site.sink) == [{
        "tripwire_id": "canary_reuse",
        "reasons": ["tried the fake DATABASE_URL in /opt/app/.env as the /admin password"],
    }]
    assert "FAKE-CANARY" not in repr(site.sink.events)


async def test_canary_in_a_url_trips(site):
    async with site() as c:
        await c.get("/api/login?key=FAKE-CANARY-PAY-0c19a8")
    assert [t["tripwire_id"] for t in trips(site.sink)] == ["canary_reuse"]
    assert "PAYMENTS_API_KEY" in trips(site.sink)[0]["reasons"][0]


async def test_agents_hello_trips_once_per_source(site):
    async with site() as c:
        r = await c.get("/agents/hello?src=readme")
        await c.get("/agents/hello?src=readme")
        await c.post("/agents/hello?src=site")
    assert r.status_code == 200 and "Thanks for identifying yourself" in r.text
    assert [t["reasons"][0] for t in trips(site.sink)] == [
        "visited /agents/hello, as the README in /root asks",
        "visited /agents/hello, as the website's homepage asks",
    ]


async def test_big_bodies_are_refused(site):
    async with site() as c:
        r = await c.post("/admin", content=b"username=a&password=" + b"x" * (MAX_BODY + 10),
                         headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    assert "login_fail" not in kinds(site.sink)


async def test_requests_group_into_sessions_by_ip_and_idle_time(site):
    async with site() as c:
        await c.get("/", headers={"user-agent": "curl/8.5.0"})
        site.clock.t += 599
        await c.get("/admin")
    async with site("198.51.100.9") as other:
        await other.get("/")
    site.clock.t += 601
    async with site() as c:
        await c.get("/robots.txt")
    events = site.sink.events
    for e in events:
        parse_raw_event(e)
    assert {e["protocol"] for e in events} == {"http"}
    starts = [e for e in events if e["type"] == "session_start"]
    assert len(starts) == 3
    assert starts[0]["detail"] == {"client": "curl/8.5.0"}
    first = starts[0]["session_id"]
    [end] = [e for e in events if e["type"] == "session_end"]
    assert end["session_id"] == first and end["detail"] == {"duration_s": 599.0, "command_count": 2}
    assert [e["source"] for e in starts] == ["wild", "team", "wild"]
    assert starts[2]["session_id"] != first
    # the sweeper ends the quiet ones; close ends the rest
    site.clock.t += 601
    site.sessions.sweep()
    assert site.sessions.by_ip == {}
    assert kinds(site.sink).count("session_end") == 3


async def test_real_uvicorn_on_localhost(tmp_path, base):
    sink = MemorySink()
    settings = replace(Settings(), ssh_host="127.0.0.1", http_port=0)
    web = WebServer(settings, sink, frozenset(), find_canaries(base), base)
    assert await web.start()
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"http://127.0.0.1:{web.port}/agents/hello?src=robots")
            assert r.status_code == 200 and r.headers["server"] == SERVER
            # uvicorn's own server and date headers are off, so there's one of each
            assert r.headers.get_list("server") == [SERVER] and len(r.headers.get_list("date")) == 1
            # nginx casing and order on the wire
            names = [n for n, _ in r.headers.raw]
            assert names[:2] == [b"Server", b"Date"] and b"Content-Type" in names
    finally:
        await web.close()
    assert kinds(sink) == ["session_start", "command", "tripwire", "session_end"]
    assert sink.events[0]["src_ip"] == "127.0.0.1"


async def test_bind_failure_leaves_the_rest_running(base):
    settings = replace(Settings(), ssh_host="127.0.0.1", http_port=0)
    first = WebServer(settings, MemorySink(), frozenset(), {}, base)
    assert await first.start()
    try:
        taken = replace(settings, http_port=first.port)
        second = WebServer(taken, MemorySink(), frozenset(), {}, base)
        assert not await second.start()
        await second.close()
    finally:
        await first.close()
    await asyncio.sleep(0)


def test_http_port_setting():
    assert Settings.from_env({}).http_port == 8080
    assert Settings.from_env({"TRAP_HTTP_PORT": "80"}).http_port == 80
