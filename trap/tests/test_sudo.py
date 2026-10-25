"""fake sudo in the engine. the ssh side (prompt, echo off, events) is in test_ssh.py."""

import time

import pytest

from honeypot.shell.commands.sudo import needs_password, parse

PW = "guest-Pw-91zq"


@pytest.fixture
def guest(engine, base):
    """an interactive guest session whose sudo check takes PW."""
    state = engine.new_state("guest", tty=True, base=base)
    state.sudo_check = lambda pw: pw == PW

    def run(line):
        res = engine.run(state, line)
        run.code = res.code
        return res.out

    run.state = state
    return run


def unlock(sh):
    # what the ssh layer does after a right password at the prompt
    sh.state.sudo_until = time.time() + 900


def test_parse_stops_at_the_command():
    assert parse(["ls", "-la", "/root"]) == ({}, ["ls", "-la", "/root"])
    assert parse(["-u", "deploy", "id", "-u"]) == ({"u": "deploy"}, ["id", "-u"])
    assert parse(["-iu", "root"]) == ({"i": True, "u": "root"}, [])
    assert parse(["-S", "--", "-weird"]) == ({"S": True}, ["-weird"])
    assert parse(["--user=deploy", "FOO=1", "env"]) == ({"u": "deploy"}, ["env"])


def test_needs_password(guest):
    st = guest.state
    for line in ("sudo id", "cd /tmp && sudo -u deploy ls", "echo a | sudo tee /etc/x", "sudo -i", "sudo -l", "/usr/bin/sudo whoami"):
        assert needs_password(st, line), line
    for line in ("echo sudo", "sudo -S id", "sudo -n id", "sudo -k", "sudo -V", "sudo", "ls 'unterminated"):
        assert not needs_password(st, line), line
    unlock(guest)
    assert not needs_password(st, "sudo id")


def test_sudo_runs_as_root_once_unlocked(guest):
    assert "a password is required" in guest("sudo id 2>&1")
    unlock(guest)
    assert guest("sudo id") == "uid=0(root) gid=0(root) groups=0(root)\n"
    assert guest("sudo whoami; whoami") == "root\nguest\n"
    # root can read what guest can't
    assert "Permission denied" in guest("cat /etc/shadow 2>&1")
    assert guest("sudo cat /etc/shadow").startswith("root:")
    guest("sudo touch /etc/made-by-sudo")
    assert guest.state.fs.get("/etc/made-by-sudo").owner == "root"
    assert guest.state.user == "guest"


def test_sudo_dash_s_reads_the_password_from_stdin(guest):
    assert guest(f"echo {PW} | sudo -S whoami 2>/dev/null") == "root\n"
    guest("sudo -k")
    out = guest(f"echo {PW} | sudo -S whoami 2>&1")
    assert "[sudo] password for guest: " in out and "root\n" in out
    # and it's cached now, like real sudo
    assert guest("sudo whoami") == "root\n"


def test_wrong_password_fails(engine, base, guest):
    out = guest("echo nope | sudo -S id 2>&1")
    assert "Sorry, try again." in out and "sudo: 1 incorrect password attempt" in out and guest.code == 1
    assert "uid=0" not in out
    guest.state.sudo_denied = "sudo: 3 incorrect password attempts\n"
    assert guest("sudo id 2>&1") == "sudo: 3 incorrect password attempts\n"


def test_other_users_never_get_in(engine, base):
    # deploy's check never says yes: only guest and team have a password sudo takes
    state = engine.new_state("deploy", tty=True, base=base)
    state.sudo_check = lambda pw: False
    res = engine.run(state, "echo whatever | sudo -S id 2>&1")
    assert res.code == 1 and "uid=0" not in res.out


def test_no_terminal_no_password(engine, base):
    state = engine.new_state("guest", tty=False, base=base)
    state.sudo_check = lambda pw: pw == PW
    assert "a terminal is required to read the password" in engine.run(state, "sudo id 2>&1").out
    assert engine.run(state, f"echo {PW} | sudo -S id").out.endswith("uid=0(root) gid=0(root) groups=0(root)\n")
    assert engine.run(engine.new_state("guest", tty=False, base=base), "sudo -n id 2>&1").out == "sudo: a password is required\n"


def test_root_needs_no_password(sh):
    assert sh("sudo id") == "uid=0(root) gid=0(root) groups=0(root)\n"


def test_root_shells_and_exit(guest):
    unlock(guest)
    guest("cd /tmp")
    assert guest("sudo -i") == ""
    st = guest.state
    assert st.user == "root" and st.cwd == "/root" and st.prompt().endswith("# ")
    assert guest("whoami; echo $HOME $SUDO_USER") == "root\n/root guest\n"
    assert guest("exit") == "logout\n"
    assert st.user == "guest" and st.cwd == "/tmp" and not st.exit_requested
    assert st.env["HOME"] == "/home/guest"
    guest("sudo su")
    assert st.user == "root" and st.cwd == "/tmp"
    assert guest("exit") == "exit\n" and st.user == "guest"
    guest("sudo su -")
    assert st.cwd == "/root"
    guest("exit")
    # the last exit ends the session
    guest("exit")
    assert st.exit_requested


def test_sudo_odds_and_ends(guest):
    unlock(guest)
    assert guest("sudo cd /tmp 2>&1") == "sudo: cd: command not found\n"
    assert "sudo: nosuchcmd: command not found" in guest("sudo nosuchcmd 2>&1")
    assert "unknown user nobodyhere" in guest("sudo -u nobodyhere id 2>&1")
    assert guest("sudo -u deploy whoami") == "deploy\n"
    assert "(ALL : ALL) ALL" in guest("sudo -l")
    assert guest("sudo -V").startswith("Sudo version 1.9.9")
    assert "usage: sudo -h | -K | -k | -V" in guest("sudo 2>&1") and guest.code == 1
    guest("sudo -k")
    assert "a password is required" in guest("sudo id 2>&1")


def test_guest_home_comes_from_skel_with_the_readme(engine, base):
    state = engine.new_state("guest", tty=False, base=base)
    readme = state.fs.get("/home/guest/README.md")
    assert readme.content == base.nodes["/root/README.md"].content and readme.owner == "guest"
    assert {".bashrc", ".profile", ".bash_logout", "README.md"} <= set(state.fs.listdir("/home/guest"))
