import pytest

from honeypot.shell.parser import ParseError, parse_command, simple_expander, split_line

ex = simple_expander({"HOME": "/root", "USER": "root", "X": "a b"}, run=lambda s: "SUB(" + s + ")")


def argv(raw):
    return parse_command(raw, ex).argv


def test_split_connectors():
    assert split_line("a; b && c || d") == [(";", ["a"]), (";", ["b"]), ("&&", ["c"]), ("||", ["d"])]
    assert split_line("cat x | grep y | wc -l") == [(";", ["cat x", "grep y", "wc -l"])]
    assert split_line("echo 'a;b' \"c|d\"") == [(";", ["echo 'a;b' \"c|d\""])]
    assert split_line("echo $(ls; pwd) | wc") == [(";", ["echo $(ls; pwd)", "wc"])]
    assert split_line("ls 2>&1 | head") == [(";", ["ls 2>&1", "head"])]
    assert split_line("echo hi # a comment") == [(";", ["echo hi"])]
    assert split_line("") == []


@pytest.mark.parametrize("bad", ["| ls", "ls ||", "echo 'open", "a ;; b"])
def test_split_errors(bad):
    with pytest.raises(ParseError):
        split_line(bad)


def test_quotes_and_vars():
    assert argv("echo 'a  $USER' \"b $USER\" c\\ d") == ["echo", "a  $USER", "b root", "c d"]
    assert argv("echo $X") == ["echo", "a", "b"]
    assert argv('echo "$X"') == ["echo", "a b"]
    assert argv("echo ${USER}x $NOPE end") == ["echo", "rootx", "end"]
    assert argv("echo ~ ~/x") == ["echo", "/root", "/root/x"]
    assert argv("echo $(whoami)") == ["echo", "SUB(whoami)"]
    assert argv("echo `id`") == ["echo", "SUB(id)"]


def test_redirects():
    cmd = parse_command("echo hi > /tmp/a 2>/dev/null >> b", ex)
    assert cmd.argv == ["echo", "hi"]
    assert [(r.fd, r.op, r.target) for r in cmd.redirects] == [(1, ">", "/tmp/a"), (2, ">", "/dev/null"), (1, ">>", "b")]
    cmd = parse_command("ls 2>&1", ex)
    assert [(r.fd, r.op, r.target) for r in cmd.redirects] == [(2, "dup", "1")]
    cmd = parse_command("cat < in", ex)
    assert [(r.fd, r.op, r.target) for r in cmd.redirects] == [(0, "<", "in")]
    with pytest.raises(ParseError):
        parse_command("echo >", ex)


def test_assignments():
    cmd = parse_command("A=1 B=two", ex)
    assert cmd.argv == [] and cmd.assigns == [("A", "1"), ("B", "two")]
    assert parse_command("echo A=1", ex).argv == ["echo", "A=1"]
