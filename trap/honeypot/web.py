"""the fake website on port 80: fastapi, served by uvicorn inside the trap's own loop.

pages come from the same fake fs the shell shows, so `cat /var/www/html/index.html`
and `GET /` agree. requests from one ip with less than 10 minutes between them are
one http session. /admin always says no and keeps only the username. nothing a
request sends is ever run or fetched.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import logging
import posixpath
import time
from dataclasses import dataclass
from email.utils import formatdate
from typing import Callable
from urllib.parse import parse_qs, unquote_plus

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from starlette.exceptions import HTTPException

from .config import Settings
from .events import SessionEvents, Sink, clean_ip
from .shell.engine import load_base
from .tripwires import HELLO_PATH, Trip, Tripwires
from .vfs import BaseFS

log = logging.getLogger("honeypot.web")

SESSION_IDLE = 600.0
SWEEP_EVERY = 30.0
MAX_SESSIONS = 5000
MAX_BODY = 16_384
MAX_USER_AGENT = 256
SERVER = "nginx/1.18.0 (Ubuntu)"
WEB_ROOT = "/var/www/html"
TYPES = {".html": "text/html", ".css": "text/css", ".txt": "text/plain", ".js": "application/javascript"}
REASONS = {200: "OK", 404: "Not Found", 405: "Not Allowed", 413: "Request Entity Too Large", 500: "Internal Server Error"}


def nginx_error(status: int) -> HTMLResponse:
    title = f"{status} {REASONS.get(status, 'Error')}"
    body = (
        f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n"
        f"<center><h1>{title}</h1></center>\r\n<hr><center>{SERVER}</center>\r\n</body>\r\n</html>\r\n"
    )
    return HTMLResponse(body, status_code=status)


ADMIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sign in | Quillfern admin</title>
  <link rel="stylesheet" href="/static/site.css">
</head>
<body>
  <header><h1>Quillfern Tile &amp; Stone</h1><p>Staff sign in</p></header>
  <main>
    {error}<form method="post" action="/admin">
      <p><label>Username <input name="username" autocomplete="username" value="{username}"></label></p>
      <p><label>Password <input name="password" type="password" autocomplete="current-password"></label></p>
      <p><button type="submit">Sign in</button></p>
    </form>
  </main>
</body>
</html>
"""

HELLO_PAGE = (
    "Hello. Thanks for identifying yourself.\n"
    "This visit was recorded as coming from an automated agent. Nothing else happens.\n"
)


@dataclass
class HttpSession:
    events: SessionEvents
    wires: Tripwires
    started: float
    last: float
    requests: int = 0


class HttpSessions:
    """one session per ip until it goes quiet for SESSION_IDLE seconds."""

    def __init__(self, sink: Sink, team_ips: frozenset[str], canaries: dict[str, str],
                 clock: Callable[[], float] = time.monotonic):
        self.sink = sink
        self.team_ips = team_ips
        self.canaries = canaries
        self.clock = clock
        self.by_ip: dict[str, HttpSession] = {}

    def touch(self, ip: str, user_agent: str) -> HttpSession:
        now = self.clock()
        try:
            key = clean_ip(ip)
        except ValueError:
            key = "0.0.0.0"
        s = self.by_ip.get(key)
        if s is not None and now - s.last > SESSION_IDLE:
            self._end(key)
            s = None
        if s is None:
            if len(self.by_ip) >= MAX_SESSIONS:
                self._end(min(self.by_ip, key=lambda k: self.by_ip[k].last))
            events = SessionEvents(self.sink, key, protocol="http")
            events.resolve("team" if key in self.team_ips else "wild")
            events.session_start(user_agent[:MAX_USER_AGENT] or None)
            s = self.by_ip[key] = HttpSession(events, Tripwires(self.canaries), now, now)
        s.last = now
        return s

    def sweep(self) -> None:
        now = self.clock()
        for key in [k for k, s in self.by_ip.items() if now - s.last > SESSION_IDLE]:
            self._end(key)

    def close(self) -> None:
        for key in list(self.by_ip):
            self._end(key)

    def _end(self, key: str) -> None:
        s = self.by_ip.pop(key)
        s.events.session_end(s.last - s.started, s.requests)


def _client_ip(request: Request) -> str:
    # never trust x-forwarded-for; nothing sits in front of us
    return request.client.host if request.client else "0.0.0.0"


async def _read_body(request: Request) -> bytes | None:
    """the body, or None if it's bigger than MAX_BODY."""
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            return None
    return body


def _title(name: bytes) -> bytes:
    return b"-".join(p.capitalize() for p in name.split(b"-"))


def nginx_headers(app):
    """Server and Date first, names in nginx's casing. starlette lowercases them, which gives us away."""

    async def wrapped(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)

        async def send_nginx(message):
            if message["type"] == "http.response.start":
                rest = [(_title(n), v) for n, v in message.get("headers", []) if n.lower() not in (b"server", b"date")]
                first = [(b"Server", SERVER.encode()), (b"Date", formatdate(usegmt=True).encode())]
                message = {**message, "headers": first + rest}
            await send(message)

        await app(scope, receive, send_nginx)

    return wrapped


def build_app(sessions: HttpSessions, base: BaseFS):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def page(path: str) -> Response:
        node = base.nodes.get(path)
        if node is None or node.type != "file":
            return nginx_error(404)
        kind = TYPES.get(posixpath.splitext(path)[1], "application/octet-stream")
        # nginx sends static files without a charset
        return Response(node.content, headers={"content-type": kind})

    def trips(request: Request, found: list[Trip]) -> None:
        request.state.trips += found

    @app.middleware("http")
    async def track(request: Request, call_next):
        t0 = time.perf_counter()
        s = sessions.touch(_client_ip(request), request.headers.get("user-agent", ""))
        request.state.session = s
        request.state.trips = []
        try:
            response = await call_next(request)
        except Exception:
            log.exception("web handler failed")
            response = nginx_error(500)
        s.requests += 1
        line = f"{request.method} {request.url.path}" + (f"?{request.url.query}" if request.url.query else "")
        ms = int((time.perf_counter() - t0) * 1000)
        status = response.status_code
        s.events.command(line, f"{status} {REASONS.get(status, '')}".strip(), ms, "engine")
        found = request.state.trips + s.wires.reused(unquote_plus(line), "in a web request")
        for wire, reasons in found:
            s.events.tripwire(wire, reasons)
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return nginx_error(exc.status_code)

    @app.api_route("/", methods=["GET", "HEAD"])
    @app.api_route("/index.html", methods=["GET", "HEAD"])
    async def home():
        return page(f"{WEB_ROOT}/index.html")

    @app.api_route("/robots.txt", methods=["GET", "HEAD"])
    async def robots():
        return page(f"{WEB_ROOT}/robots.txt")

    @app.api_route("/static/{name}", methods=["GET", "HEAD"])
    async def static(name: str):
        return page(f"{WEB_ROOT}/static/{posixpath.basename(name)}")

    @app.get("/admin")
    async def admin_form():
        return HTMLResponse(ADMIN_PAGE.format(error="", username=""))

    @app.post("/admin")
    async def admin_login(request: Request):
        body = await _read_body(request)
        if body is None:
            return nginx_error(413)
        form = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        username = (form.get("username") or [""])[0][:256]
        password = (form.get("password") or [""])[0]
        s: HttpSession = request.state.session
        # only the canary label survives, never the password
        trips(request, s.wires.secret(password, "/admin password") + s.wires.secret(username, "/admin username"))
        del password, form, body
        s.events.login_fail(username)
        error = '<p class="error">Invalid username or password.</p>\n    '
        return HTMLResponse(ADMIN_PAGE.format(error=error, username=html.escape(username)))

    @app.api_route(HELLO_PATH, methods=["GET", "HEAD", "POST"])
    async def agent_hello(request: Request, src: str = ""):
        s: HttpSession = request.state.session
        trips(request, s.wires.hello(src))
        return PlainTextResponse(HELLO_PAGE)

    @app.api_route("/{rest:path}", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    async def not_found(rest: str):
        return nginx_error(404)

    return nginx_headers(app)


class _Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self):
        # the trap's main owns signals; ssh keeps running whatever http does
        yield


class WebServer:
    def __init__(self, settings: Settings, sink: Sink, team_ips: frozenset[str], canaries: dict[str, str],
                 base: BaseFS | None = None):
        self.sessions = HttpSessions(sink, team_ips, canaries)
        self.app = build_app(self.sessions, base or load_base())
        config = uvicorn.Config(
            self.app, host=settings.ssh_host, port=settings.http_port,
            http="h11", ws="none", lifespan="off", log_config=None, log_level="warning",
            access_log=False, server_header=False, date_header=False, proxy_headers=False,
            limit_concurrency=200, timeout_keep_alive=5, h11_max_incomplete_event_size=16_384,
        )
        self.server = _Server(config)
        self._task: asyncio.Task | None = None
        self._sweeper: asyncio.Task | None = None

    async def _serve(self) -> None:
        try:
            await self.server.serve()
        except SystemExit:
            # uvicorn exits when it can't bind; keep the ssh side alive
            log.error("http trap could not start on port %s", self.server.config.port)

    async def start(self) -> bool:
        self._task = asyncio.create_task(self._serve())
        while not self.server.started and not self._task.done():
            await asyncio.sleep(0.01)
        if not self.server.started:
            return False
        self._sweeper = asyncio.create_task(self._sweep())
        return True

    @property
    def port(self) -> int:
        return self.server.servers[0].sockets[0].getsockname()[1]

    async def _sweep(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_EVERY)
            self.sessions.sweep()

    async def close(self) -> None:
        self.server.should_exit = True
        if self._sweeper:
            self._sweeper.cancel()
        await asyncio.gather(*[t for t in (self._task, self._sweeper) if t], return_exceptions=True)
        self.sessions.close()
