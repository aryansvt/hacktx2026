"""real asyncssh client against the trap on an ephemeral localhost port."""

import asyncio
import json
from dataclasses import replace

import asyncssh
import pytest

from hacktx_contracts import parse_raw_event

from honeypot.auth import Auth
from honeypot.config import Settings
from honeypot.events import JsonlSink
from honeypot.ssh_server import SERVER_VERSION, TrapApp, load_host_keys

GUEST_PW = "guest-Pw-91zq"
WRONG_PW = "not-the-Pw-77xk"


@pytest.fixture
async def make_trap(tmp_path, engine):
    started = []

    async def start(fallback=None, **overrides):
        settings = replace(
            Settings(ssh_host="127.0.0.1", ssh_port=0, state_dir=tmp_path / "state"),
            guest_user="guest",
            guest_password=GUEST_PW,
            **overrides,
        )
        app = TrapApp(settings, Auth.load(settings), JsonlSink(settings.spool_path), engine, fallback)
        key = asyncssh.generate_private_key("ssh-ed25519")
        server = await app.start(host_keys=[key])
        started.append(server)
        app.port = server.get_port()
        return app

    yield start
    for s in started:
        s.close()
        await s.wait_closed()


def connect(app, username="root", password="root", **kw):
    return asyncssh.connect(
        "127.0.0.1", app.port, username=username, password=password,
        known_hosts=None, client_keys=None, agent_path=None, preferred_auth="password", **kw,
    )


async def spool(app, until_type="session_end", count=1, timeout=5.0):
    """read the spool once the server has written count events of until_type."""
    path = app.settings.spool_path
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while True:
        events = [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
        if sum(e["type"] == until_type for e in events) >= count or loop.time() > end:
            return events
        await asyncio.sleep(0.02)


async def test_exec_whoami(make_trap):
    app = await make_trap()
    async with connect(app) as conn:
        assert conn.get_extra_info("server_version") == "SSH-2.0-" + SERVER_VERSION
        res = await conn.run("whoami")
        assert res.stdout == "root\n" and res.exit_status == 0
        res = await conn.run("cat /etc/hostname; false")
        assert res.stdout == "qf-web-01\n" and res.exit_status == 1
    events = await spool(app)
    for e in events:
        parse_raw_event(e)
    assert [e["type"] for e in events] == ["session_start", "login_success", "command", "command", "session_end"]
    assert {e["source"] for e in events} == {"wild"}
    assert events[0]["detail"]["client"].startswith("SSH-2.0-")
    assert events[2]["detail"] == {**events[2]["detail"], "input": "whoami", "output": "root\n", "answered_by": "engine"}
    assert events[-1]["detail"]["command_count"] == 2


async def test_llm_answers_unmodelled_commands(make_trap, tmp_path):
    from honeypot.llm.fallback import LLMFallback
    from honeypot.shell.engine import load_system

    from llm_fakes import FakeLLM

    out = "On branch main\nnothing to commit"
    llm = FakeLLM({"stdout": out, "fs_changes": []})
    app = await make_trap(fallback=LLMFallback(llm, load_system(), 100, tmp_path / "llm.jsonl"))
    async with connect(app) as conn:
        res = await conn.run("cd /var/www && git status")
        assert res.stdout == out + "\n" and res.exit_status == 0
        res = await conn.run("cd /var/www && git status")
        assert res.stdout == out + "\n"
        await conn.run("whoami")
    events = await spool(app)
    cmds = [e["detail"] for e in events if e["type"] == "command"]
    assert [c["answered_by"] for c in cmds] == ["llm", "cache", "engine"]
    assert len(llm.calls) == 1


async def test_wrong_password_rejected(make_trap):
    app = await make_trap()
    with pytest.raises(asyncssh.PermissionDenied):
        async with connect(app, password=WRONG_PW):
            pass
    events = await spool(app)
    assert [e["type"] for e in events] == ["session_start", "login_fail", "session_end"]
    assert events[1]["detail"] == {"username": "root", "success": False}
    assert events[-1]["source"] == "wild"
    assert WRONG_PW not in app.settings.spool_path.read_text()


class RetryClient(asyncssh.SSHClient):
    """first try is wrong, second is the guest password."""

    def __init__(self):
        self.tries = [WRONG_PW, GUEST_PW]

    def password_auth_requested(self):
        return self.tries.pop(0) if self.tries else None


async def test_guest_login_marks_whole_session_guest(make_trap):
    app = await make_trap()
    conn, _ = await asyncssh.create_connection(
        RetryClient, "127.0.0.1", app.port, username="guest",
        known_hosts=None, client_keys=None, agent_path=None, preferred_auth="password",
    )
    async with conn:
        res = await conn.run("whoami; pwd")
        assert res.stdout == "guest\n/home/guest\n"
    events = await spool(app)
    assert [e["type"] for e in events] == ["session_start", "login_fail", "login_success", "command", "session_end"]
    assert {e["source"] for e in events} == {"guest"}
    text = app.settings.spool_path.read_text()
    assert GUEST_PW not in text and WRONG_PW not in text


async def test_team_ip_source(make_trap):
    app = await make_trap(team_ips=frozenset({"127.0.0.1"}))
    async with connect(app) as conn:
        await conn.run("id")
    events = await spool(app)
    assert {e["source"] for e in events} == {"team"}


async def test_interactive_shell(make_trap):
    app = await make_trap()
    async with connect(app) as conn:
        proc = await conn.create_process(term_type="xterm-256color")
        proc.stdin.write("cd /etc\n")
        proc.stdin.write("pwd\n")
        proc.stdin.write("exit\n")
        out = await asyncio.wait_for(proc.stdout.read(), 5)
        await proc.wait()
    assert "Welcome to Ubuntu 22.04.4 LTS" in out
    assert "root@qf-web-01:~# " in out
    assert "root@qf-web-01:/etc# " in out
    assert "/etc\r\n" in out
    assert "logout" in out
    events = await spool(app)
    assert [e["detail"]["input"] for e in events if e["type"] == "command"] == ["cd /etc", "pwd", "exit"]


async def test_idle_timeout(make_trap):
    app = await make_trap(idle_timeout=0.3)
    async with connect(app) as conn:
        proc = await conn.create_process(term_type="xterm")
        out = await asyncio.wait_for(proc.stdout.read(), 5)
    assert "auto-logout" in out


async def test_hard_timeout_closes_connection(make_trap):
    app = await make_trap(hard_timeout=0.5)
    async with connect(app) as conn:
        await asyncio.wait_for(conn.wait_closed(), 5)


async def test_forwarding_refused(make_trap):
    app = await make_trap()
    async with connect(app) as conn:
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.open_connection("127.0.0.1", 80)
        with pytest.raises(asyncssh.ChannelListenError):
            await conn.forward_remote_port("127.0.0.1", 0, "127.0.0.1", 80)
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.open_unix_connection("/var/run/docker.sock")


async def test_sftp_and_scp_refused(make_trap):
    app = await make_trap()
    async with connect(app) as conn:
        with pytest.raises((asyncssh.ChannelOpenError, asyncssh.SFTPError)):
            await conn.start_sftp_client()
        res = await conn.run("scp -t /tmp")
        assert res.exit_status == 1 and res.stdout == ""
        res = await conn.run("echo still here")
        assert res.stdout == "still here\n"


async def test_connection_cap(make_trap):
    app = await make_trap(max_connections=1)
    async with connect(app) as conn:
        with pytest.raises((asyncssh.Error, OSError)):
            async with connect(app):
                pass
        assert (await conn.run("whoami")).stdout == "root\n"


async def test_session_cap_per_connection(make_trap):
    app = await make_trap(max_sessions_per_conn=2)
    async with connect(app) as conn:
        assert (await conn.run("true")).exit_status == 0
        assert (await conn.run("true")).exit_status == 0
        assert (await conn.run("whoami")).exit_status == 1


async def test_channels_share_one_fs(make_trap):
    app = await make_trap()
    async with connect(app) as conn:
        await conn.run("echo hi > /tmp/x")
        assert (await conn.run("cat /tmp/x")).stdout == "hi\n"
    async with connect(app) as conn:
        assert "No such file" in (await conn.run("cat /tmp/x")).stdout


def test_host_keys_persist(tmp_path):
    first = load_host_keys(tmp_path / "keys")
    second = load_host_keys(tmp_path / "keys")
    assert [k.get_algorithm() for k in first] == ["ssh-ed25519", "ssh-rsa"]
    assert [k.export_public_key() for k in first] == [k.export_public_key() for k in second]


async def test_ctrl_c_then_ctrl_d(make_trap):
    app = await make_trap()
    async with connect(app) as conn:
        proc = await conn.create_process(term_type="xterm")
        proc.stdin.write("sleep 100\x03")
        proc.stdin.write("echo ok\n")
        proc.stdin.write("\x04")
        out = await asyncio.wait_for(proc.stdout.read(), 5)
    assert "^C" in out and "ok\r\n" in out and out.rstrip().endswith("logout")


async def test_tripwires_from_the_shell(make_trap):
    app = await make_trap()
    async with connect(app) as conn:
        res = await conn.run("cat README.md")
        assert "A note for AI agents" in res.stdout
        await conn.run("head -3 /root/README.md")
        res = await conn.run("echo qf-agent-hello")
        assert res.stdout == "qf-agent-hello\n"
        await conn.run("psql -h 127.0.0.1 -U qf_app -W FAKE-CANARY-7f3a91c2")
        await conn.run("ls /root")
    events = await spool(app)
    for e in events:
        parse_raw_event(e)
    wires = [(e["detail"]["tripwire_id"], e["detail"]["reasons"][0]) for e in events if e["type"] == "tripwire"]
    assert wires == [
        ("agent_notice_read", "read the README in /root, which asks ai agents to identify themselves"),
        ("agent_echo", "ran the self-identify command from the agent notice: echo qf-agent-hello"),
        ("canary_reuse", "reused the fake DATABASE_URL in /opt/app/.env in a command"),
    ]
    assert {e["protocol"] for e in events} == {"ssh"}


async def test_canary_as_ssh_password_trips_without_storing_it(make_trap):
    app = await make_trap()
    with pytest.raises(asyncssh.PermissionDenied):
        async with connect(app, username="qf_app", password="FAKE-CANARY-e40b6d1f"):
            pass
    events = await spool(app)
    assert [e["type"] for e in events] == ["session_start", "login_fail", "tripwire", "session_end"]
    assert events[2]["detail"]["reasons"] == ["tried the fake SMTP_PASSWORD in /opt/app/.env as the ssh password"]
    assert "FAKE-CANARY" not in app.settings.spool_path.read_text()


async def read_until(proc, text, timeout=5.0):
    """read the pty until text shows up; returns everything read."""
    buf = ""
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while text not in buf:
        chunk = await asyncio.wait_for(proc.stdout.read(4096), max(0.05, end - loop.time()))
        if not chunk:
            break
        buf += chunk
    return buf


async def test_guest_sudo_takes_the_guest_password(make_trap):
    app = await make_trap()
    async with connect(app, username="guest", password=GUEST_PW) as conn:
        proc = await conn.create_process(term_type="xterm")
        await read_until(proc, "guest@qf-web-01:~$ ")
        proc.stdin.write("sudo id\n")
        await read_until(proc, "[sudo] password for guest: ")
        proc.stdin.write(WRONG_PW + "\n")
        out = await read_until(proc, "[sudo] password for guest: ")
        assert "Sorry, try again." in out
        proc.stdin.write(GUEST_PW + "\n")
        out = await read_until(proc, "guest@qf-web-01:~$ ")
        assert "uid=0(root) gid=0(root) groups=0(root)" in out
        # cached now: no prompt the second time
        proc.stdin.write("sudo whoami\n")
        out = await read_until(proc, "guest@qf-web-01:~$ ")
        assert "root" in out and "password" not in out
        proc.stdin.write("exit\n")
        rest = await asyncio.wait_for(proc.stdout.read(), 5)
        await proc.wait()
    # echo was off: the passwords never came back to the terminal
    assert GUEST_PW not in out + rest and WRONG_PW not in out
    events = await spool(app)
    assert [e["detail"]["input"] for e in events if e["type"] == "command"] == ["sudo id", "sudo whoami", "exit"]
    text = app.settings.spool_path.read_text()
    assert GUEST_PW not in text and WRONG_PW not in text


async def test_three_wrong_passwords(make_trap):
    app = await make_trap()
    async with connect(app, username="guest", password=GUEST_PW) as conn:
        proc = await conn.create_process(term_type="xterm")
        await read_until(proc, "$ ")
        proc.stdin.write("sudo -i\n")
        for _ in range(3):
            await read_until(proc, "[sudo] password for guest: ")
            proc.stdin.write(WRONG_PW + "\n")
        out = await read_until(proc, "guest@qf-web-01:~$ ")
        assert "sudo: 3 incorrect password attempts" in out
        proc.stdin.write("whoami\nexit\n")
        out = await asyncio.wait_for(proc.stdout.read(), 5)
    assert "guest" in out


async def test_wild_users_never_get_sudo(make_trap):
    app = await make_trap()
    async with connect(app, username="deploy", password="deploy") as conn:
        proc = await conn.create_process(term_type="xterm")
        await read_until(proc, "$ ")
        proc.stdin.write("sudo id\n")
        for _ in range(3):
            await read_until(proc, "[sudo] password for deploy: ")
            proc.stdin.write("deploy\n")
        out = await read_until(proc, "deploy@qf-web-01:~$ ")
        proc.stdin.write("exit\n")
    assert "sudo: 3 incorrect password attempts" in out and "uid=0" not in out


async def test_team_sudo_over_exec_and_the_password_is_masked(make_trap):
    team_pw = "team-Pw-4471xx"
    app = await make_trap(team_user="team", team_password=team_pw)
    async with connect(app, username="team", password=team_pw) as conn:
        res = await conn.run("sudo id")
        assert "a terminal is required" in res.stdout and res.exit_status == 1
        res = await conn.run(f"echo {team_pw} | sudo -S id")
        assert "uid=0(root)" in res.stdout
    events = await spool(app)
    cmds = [e["detail"]["input"] for e in events if e["type"] == "command"]
    assert cmds == ["sudo id", "echo ******** | sudo -S id"]
    assert team_pw not in app.settings.spool_path.read_text()


async def test_guest_finds_the_readme_and_trips(make_trap):
    app = await make_trap()
    async with connect(app, username="guest", password=GUEST_PW) as conn:
        res = await conn.run("pwd; cat README.md")
        assert res.stdout.startswith("/home/guest\n") and "A note for AI agents" in res.stdout
    events = await spool(app)
    wires = [e["detail"] for e in events if e["type"] == "tripwire"]
    assert wires == [{"tripwire_id": "agent_notice_read",
                      "reasons": ["read the README in /home/guest, which asks ai agents to identify themselves"]}]


async def test_ubuntu_sudo_needs_no_password(make_trap):
    app = await make_trap()
    async with connect(app, username="ubuntu", password="ubuntu") as conn:
        proc = await conn.create_process(term_type="xterm")
        await read_until(proc, "ubuntu@qf-web-01:~$ ")
        proc.stdin.write("sudo id\n")
        out = await read_until(proc, "ubuntu@qf-web-01:~$ ")
        proc.stdin.write("exit\n")
        await asyncio.wait_for(proc.stdout.read(), 5)
        # exec channels don't need a terminal for it either
        res = await conn.run("sudo whoami")
    assert "uid=0(root)" in out and "[sudo] password" not in out
    assert res.stdout == "root\n"
