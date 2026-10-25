import time


def test_echo_printf(sh):
    assert sh("echo hello world") == "hello world\n"
    assert sh("echo -n hi") == "hi"
    assert sh("echo -e 'a\\tb'") == "a\tb\n"
    assert sh("printf '%s-%d\\n' x 5") == "x-5\n"


def test_wc(sh):
    assert sh("echo one two | wc -w") == "2\n"
    assert sh("wc -l /etc/hostname") == "1 /etc/hostname\n"
    assert sh("cat /etc/passwd | grep -c bash") == sh("grep -c bash /etc/passwd")


def test_sort_uniq(sh):
    sh("printf 'b\\na\\nb\\nc\\n' > /tmp/l")
    assert sh("sort /tmp/l") == "a\nb\nb\nc\n"
    assert sh("sort -r /tmp/l | head -n 1") == "c\n"
    assert sh("sort /tmp/l | uniq") == "a\nb\nc\n"
    assert sh("sort /tmp/l | uniq -c") == "      1 a\n      2 b\n      1 c\n"
    sh("printf '10\\n9\\n100\\n' > /tmp/n")
    assert sh("sort -n /tmp/n") == "9\n10\n100\n"


def test_grep(sh):
    assert sh("grep -i ROOT /etc/hostname") == ""
    assert sh.state.last_status == 1
    assert sh("grep -v x /etc/hostname") == "qf-web-01\n"
    assert sh("grep -n qf /etc/hostname") == "1:qf-web-01\n"
    assert "POSTGRES_PASSWORD" in sh("grep -r PASSWORD /opt/app")
    assert sh("grep -E '^(root|deploy):' /etc/passwd | wc -l") == "2\n"
    assert sh("grep 'ro\\(o\\)t' /etc/passwd | head -n 1").startswith("root:")
    assert "Unmatched" in sh("grep -E '(' /etc/passwd")


def test_grep_slow_pattern_is_bounded(sh):
    sh("printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!\\n' > /tmp/long")
    t = time.perf_counter()
    sh("grep -E '(a|aa)+$' /tmp/long")
    assert time.perf_counter() - t < 1.0


def test_base64(sh):
    assert sh("echo hello | base64") == "aGVsbG8K\n"
    assert sh("echo aGVsbG8K | base64 -d") == "hello\n"
    assert "invalid input" in sh("echo '!!!' | base64 -d")
