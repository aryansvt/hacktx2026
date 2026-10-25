"""shared helpers for the sim and demo scripts.

these scripts only ever talk to our own honeypot. the ssh target is TRAP_HOST
from the repo's .env and nothing else: there is no host flag, and connect()
refuses any host that isn't on the allowlist. the api is CORE_URL from .env.
every session logs in as TEAM_SSH_USER, so the trap tags it source=team and it
never counts in stats.
"""

from __future__ import annotations

import asyncio
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import asyncssh
import httpx

ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = ROOT / ".env"
DEFAULT_PORT = 22

# the prompt the trap prints, e.g. team@qf-web-01:~$
PROMPT_RE = re.compile(r"[\w.-]+@[\w.-]+:[^\n]*[$#] $")
SUDO_RE = re.compile(r"\[sudo\] password for [\w.-]+: $")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class NotAllowed(RuntimeError):
    pass


def load_env(path: Path = ENV_PATH) -> dict[str, str]:
    """plain KEY=value parser. only the .env file counts, never the shell's env."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("'\"")
    return env


ENV = load_env()


def _need(key: str) -> str:
    value = ENV.get(key, "")
    if not value:
        raise SystemExit(f"{key} is empty or missing in {ENV_PATH}")
    return value


def allowed_hosts() -> frozenset[str]:
    """the allowlist: TRAP_HOST from .env. nothing else is ever a valid target."""
    host = _need("TRAP_HOST").lower()
    if host in ("0.0.0.0", "::", "*"):
        raise SystemExit("TRAP_HOST must be the trap's address, not a wildcard")
    return frozenset({host})


def check_host(host: str) -> str:
    host = host.strip().lower()
    if host not in allowed_hosts():
        raise NotAllowed(f"refusing {host!r}: only TRAP_HOST from .env is allowed")
    return host


def api_base() -> str:
    """CORE_URL from .env, https only."""
    url = _need("CORE_URL").rstrip("/")
    parts = urlsplit(url)
    if parts.scheme != "https" and parts.hostname not in ("localhost", "127.0.0.1"):
        raise SystemExit("CORE_URL must be https")
    return url


def check_api_url(url: str) -> str:
    base = urlsplit(api_base())
    parts = urlsplit(url)
    if (parts.scheme, parts.netloc) != (base.scheme, base.netloc):
        raise NotAllowed(f"refusing {url!r}: only CORE_URL from .env is allowed")
    return url


def team_login() -> tuple[str, str]:
    return _need("TEAM_SSH_USER"), _need("TEAM_SSH_PASSWORD")


async def connect(port: int = DEFAULT_PORT, client_version: str = "", client_factory=None,
                  password: str | None = None, **kw) -> asyncssh.SSHClientConnection:
    """open an ssh connection to the trap as the team user."""
    host = check_host(ENV.get("TRAP_HOST", ""))
    user, team_pw = team_login()
    opts = dict(username=user, known_hosts=None, preferred_auth="password", connect_timeout=15)
    # a client_factory that answers password prompts itself skips this
    if client_factory is None:
        opts["password"] = team_pw if password is None else password
    else:
        opts["client_factory"] = client_factory
    if client_version:
        opts["client_version"] = client_version
    opts.update(kw)
    return await asyncssh.connect(host, port, **opts)


def strip_echo(out: str, line: str) -> str:
    """drop a pty's echo of the line from the front of the output, even if it wrapped."""
    i = j = 0
    while j < len(line) and i < len(out):
        if out[i] in "\r\n":
            i += 1
        elif out[i] == line[j]:
            i += 1
            j += 1
        else:
            return out
    if j < len(line):
        return out
    rest = out[i:].lstrip("\r")
    return rest[1:] if rest.startswith("\n") else rest


class Shell:
    """one interactive shell on the trap. send a line, read until the next prompt."""

    def __init__(self, process: asyncssh.SSHClientProcess):
        self.p = process
        self.buf = ""

    @classmethod
    async def open(cls, conn: asyncssh.SSHClientConnection, pty: bool = False) -> "Shell":
        kw = {"term_type": "xterm-256color", "term_size": (200, 50)} if pty else {}
        process = await conn.create_process(encoding="utf-8", errors="replace", **kw)
        sh = cls(process)
        sh.banner = await sh.read_prompt()
        return sh

    async def read_prompt(self, timeout: float = 30.0, on_sudo: str | None = "") -> str:
        """read until the prompt. a sudo password prompt gets an empty answer."""
        deadline = time.monotonic() + timeout
        while True:
            clean = ANSI_RE.sub("", self.buf)
            if PROMPT_RE.search(clean):
                self.buf = ""
                return PROMPT_RE.sub("", clean).replace("\r\n", "\n")
            if on_sudo is not None and SUDO_RE.search(clean):
                # never hand the team password to sudo from a sim
                self.buf = SUDO_RE.sub("", self.buf)
                try:
                    self.p.stdin.write(on_sudo + "\n")
                except BrokenPipeError:
                    return ANSI_RE.sub("", self.buf).replace("\r\n", "\n") + "\n(connection closed)"
            left = deadline - time.monotonic()
            if left <= 0:
                out, self.buf = clean, ""
                return out.replace("\r\n", "\n") + "\n(timed out waiting for the prompt)"
            try:
                chunk = await asyncio.wait_for(self.p.stdout.read(4096), left)
            except asyncio.TimeoutError:
                continue
            if not chunk:
                out, self.buf = clean, ""
                return out.replace("\r\n", "\n") + "\n(connection closed)"
            self.buf += chunk

    async def run(self, line: str, timeout: float = 30.0) -> str:
        try:
            self.p.stdin.write(line + "\n")
        except BrokenPipeError:
            return "(connection closed)"
        return strip_echo(await self.read_prompt(timeout), line)

    async def type(self, keys: str) -> None:
        self.p.stdin.write(keys)

    async def close(self) -> None:
        try:
            self.p.stdin.write("exit\n")
            await asyncio.wait_for(self.p.wait_closed(), 5)
        except Exception:
            pass


# ---- the read api on core ----

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


async def api_get(client: httpx.AsyncClient, path: str, **params) -> httpx.Response:
    url = check_api_url(api_base() + path)
    return await client.get(url, params=params or None, timeout=15)


async def find_session(client: httpx.AsyncClient, client_version: str, since: datetime,
                       until: datetime | None = None, slack_s: float = 60.0,
                       taken: set[str] = frozenset()) -> dict | None:
    """our newest team session with this ssh client string, started inside the window."""
    r = await api_get(client, "/sessions", source="team", limit=200)
    r.raise_for_status()
    want = client_version if client_version.startswith("SSH-") else f"SSH-2.0-{client_version}"
    lo = since.timestamp() - slack_s
    hi = (until or now_utc()).timestamp() + slack_s
    hits = [s for s in r.json()
            if s["session_id"] not in taken and (s["attacker"].get("client") or "") == want
            and lo <= parse_ts(s["started_at"]).timestamp() <= hi]
    hits.sort(key=lambda s: s["started_at"], reverse=True)
    return hits[0] if hits else None


def latest_reasons(events: list[dict]) -> list[str]:
    for ev in reversed(events):
        if ev.get("type") == "classified":
            return list((ev.get("detail") or {}).get("reasons") or [])
    return []


def asyncssh_client_version() -> str:
    """what asyncssh sends when no client_version is given."""
    return f"AsyncSSH_{asyncssh.__version__}"


def run(main) -> None:
    """asyncio entrypoint that turns a refused host into a clean exit."""
    # windows consoles default to a codepage that mangles wget's quotes
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        asyncio.run(main)
    except NotAllowed as e:
        raise SystemExit(str(e))
    except KeyboardInterrupt:
        raise SystemExit(130)
