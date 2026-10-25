"""asyncssh server that hands sessions to the emulated shell.

password auth only. forwarding, agent, x11, sftp and scp are all refused.
every line the client sends goes to the rules engine, never to the host.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncssh

from .auth import Auth
from .config import Settings
from .events import SessionEvents, Sink
from .shell.engine import Engine, ShellState
from .vfs import Overlay

log = logging.getLogger("honeypot.ssh")

SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
HOST_KEY_ALGS = ("ssh-ed25519", "ssh-rsa")
# exec commands for file transfer tools we don't speak
TRANSFER = ("scp", "sftp", "sftp-server", "rsync")


def load_host_keys(key_dir: Path) -> list[asyncssh.SSHKey]:
    """reuse keys from key_dir, generate any that are missing."""
    key_dir.mkdir(parents=True, exist_ok=True)
    keys = []
    for alg in HOST_KEY_ALGS:
        path = key_dir / f"ssh_host_{alg.removeprefix('ssh-')}_key"
        if path.exists():
            keys.append(asyncssh.read_private_key(str(path)))
            continue
        key = asyncssh.generate_private_key(alg)
        key.write_private_key(str(path))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        keys.append(key)
    return keys


def motd(state: ShellState) -> str:
    sysinfo = state.system
    last = datetime.now(timezone.utc) - timedelta(hours=3, minutes=17)
    return (
        f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux {sysinfo['kernel']} x86_64)\n\n"
        " * Documentation:  https://help.ubuntu.com\n"
        " * Management:     https://landscape.canonical.com\n"
        " * Support:        https://ubuntu.com/pro\n\n"
        f"Last login: {last.strftime('%a %b %d %H:%M:%S %Y')} from {state.display_ip}\n"
    )


class TrapServer(asyncssh.SSHServer):
    """one per tcp connection. a connection is one session in the event stream."""

    def __init__(self, app: "TrapApp"):
        self.app = app
        self.conn: asyncssh.SSHServerConnection | None = None
        self.events: SessionEvents | None = None
        self.refused = False
        self.started = False
        self.t0 = time.monotonic()
        self.user = ""
        self.commands = 0
        self.sessions = 0
        self.fs: Overlay | None = None
        self._hard: asyncio.TimerHandle | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        self.app.active += 1
        if self.app.active > self.app.settings.max_connections:
            self.refused = True
            conn.close()
            return
        self.events = SessionEvents(self.app.sink, conn.get_extra_info("peername")[0])
        if self.events.src_ip in self.app.auth.team_ips:
            self.events.resolve("team")
        self._hard = asyncio.get_running_loop().call_later(self.app.settings.hard_timeout, conn.close)

    def connection_lost(self, exc: Exception | None) -> None:
        self.app.active -= 1
        if self._hard:
            self._hard.cancel()
        if self.refused or not self.started or self.events is None:
            return
        self.events.session_end(time.monotonic() - self.t0, self.commands)
        # never logged in: source comes from the ip alone
        self.events.resolve(self.app.auth.source_for(self.events.src_ip, None))

    def begin_auth(self, username: str) -> bool:
        # banner grabs that never try to log in are not sessions
        if not self.started and self.events is not None:
            self.started = True
            self.events.session_start(self.conn.get_extra_info("client_version"))
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        source = self.app.auth.check(username, password)
        del password
        if self.events is None:
            return False
        if source is None:
            self.events.login_fail(username)
            return False
        self.user = username
        self.events.resolve(self.app.auth.source_for(self.events.src_ip, source))
        self.events.login_success(username)
        return True

    # every forwarding request is refused
    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return False

    def server_requested(self, listen_host, listen_port):
        return False

    def unix_connection_requested(self, dest_path):
        return False

    def unix_server_requested(self, listen_path):
        return False


class TrapApp:
    def __init__(self, settings: Settings, auth: Auth, sink: Sink, engine: Engine | None = None):
        self.settings = settings
        self.auth = auth
        self.sink = sink
        self.engine = engine or Engine()
        self.active = 0

    async def start(self, host_keys: list[asyncssh.SSHKey] | None = None) -> asyncssh.SSHAcceptor:
        s = self.settings
        keys = host_keys or load_host_keys(s.host_key_dir)
        return await asyncssh.create_server(
            lambda: TrapServer(self),
            s.ssh_host,
            s.ssh_port,
            server_host_keys=keys,
            server_version=SERVER_VERSION,
            process_factory=self.handle,
            login_timeout=s.login_timeout,
            public_key_auth=False,
            # no gss or kerberos. also skips a slow fqdn lookup per connection
            gss_host=None,
            agent_forwarding=False,
            x11_forwarding=False,
            allow_scp=False,
            sftp_factory=None,
            # junk bytes from scanners must not kill the channel
            errors="replace",
        )

    async def handle(self, process: asyncssh.SSHServerProcess) -> None:
        server: TrapServer = process.channel.get_connection().get_owner()
        server.sessions += 1
        try:
            if process.subsystem or server.sessions > self.settings.max_sessions_per_conn:
                process.exit(1)
                return
            state = self.engine.new_state(server.user or "root", tty=process.get_terminal_type() is not None)
            # channels on one connection share a filesystem, like one real box
            if server.fs is None:
                server.fs = state.fs
            else:
                state.fs = server.fs
            if process.command is not None:
                code = self.run_line(server, state, process.command, process)
                process.exit(code)
            else:
                await self.interactive(server, state, process)
        except (asyncssh.Error, OSError, ConnectionError):
            # client went away mid-write
            pass
        except Exception:
            log.exception("session handler failed")
            process.exit(1)

    def run_line(self, server: TrapServer, state: ShellState, line: str, process: asyncssh.SSHServerProcess) -> int:
        server.commands += 1
        state.history.append(line)
        t0 = time.perf_counter()
        words = line.split()
        if words and words[0].rsplit("/", 1)[-1] in TRANSFER:
            # file transfer is refused; the client sees a closed channel
            out, code = "", 1
        else:
            res = self.engine.run(state, line)
            out, code = res.out, res.code
        ms = int((time.perf_counter() - t0) * 1000)
        if server.events:
            server.events.command(line, out, ms, "engine")
        if out:
            process.stdout.write(out)
        return code & 0xFF

    async def interactive(self, server: TrapServer, state: ShellState, process: asyncssh.SSHServerProcess) -> None:
        out = process.stdout
        out.write(motd(state))
        code = 0
        prompt = True
        while not state.exit_requested:
            if prompt:
                out.write(state.prompt())
            prompt = True
            try:
                line = await asyncio.wait_for(process.stdin.readline(), self.settings.idle_timeout)
            except asyncio.TimeoutError:
                out.write("\ntimed out waiting for input: auto-logout\n")
                break
            except asyncssh.TerminalSizeChanged:
                prompt = False
                continue
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                out.write("^C\n")
                continue
            if not line:
                # ctrl-d
                out.write("logout\n")
                break
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            code = self.run_line(server, state, line, process)
        process.exit(code)
