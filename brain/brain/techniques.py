"""map commands to mitre att&ck technique ids with a lookup table."""

from __future__ import annotations

import re

from .commands import command_name, segments

# command name -> technique ids
BY_COMMAND: dict[str, tuple[str, ...]] = {
    "uname": ("T1082",), "hostname": ("T1082",), "lscpu": ("T1082",), "nproc": ("T1082",),
    "free": ("T1082",), "df": ("T1082",), "uptime": ("T1082",), "lsblk": ("T1082",),
    "dmesg": ("T1082",), "getconf": ("T1082",), "lspci": ("T1082",),
    "whoami": ("T1033",), "id": ("T1033",), "w": ("T1033",), "who": ("T1033",),
    "last": ("T1033",), "lastlog": ("T1033",),
    "wget": ("T1105",), "curl": ("T1105",), "tftp": ("T1105",), "ftpget": ("T1105",),
    "scp": ("T1105",), "aria2c": ("T1105",),
    "crontab": ("T1053.003",),
    "useradd": ("T1136.001",), "adduser": ("T1136.001",),
    "passwd": ("T1098",), "chpasswd": ("T1098",), "usermod": ("T1098",),
    "ps": ("T1057",), "top": ("T1057",), "pgrep": ("T1057",),
    "netstat": ("T1049",), "ss": ("T1049",), "lsof": ("T1049",),
    "ifconfig": ("T1016",), "ip": ("T1016",), "route": ("T1016",), "arp": ("T1016",),
    "ls": ("T1083",), "find": ("T1083",), "locate": ("T1083",),
    "iptables": ("T1562.004",), "ufw": ("T1562.004",),
    "chattr": ("T1222.002",),
    "nc": ("T1095",), "ncat": ("T1095",),
    "xmrig": ("T1496",), "minerd": ("T1496",), "cpuminer": ("T1496",),
    "shred": ("T1070.004",),
}

# regex over the whole line -> technique ids
BY_PATTERN: list[tuple[re.Pattern, tuple[str, ...]]] = [
    (re.compile(r"/proc/cpuinfo|/proc/meminfo|/etc/os-release|/etc/issue|/proc/version"), ("T1082",)),
    (re.compile(r"/etc/passwd\b"), ("T1087.001",)),
    (re.compile(r"/etc/group\b"), ("T1069.001",)),
    (re.compile(r"/etc/shadow\b"), ("T1003.008",)),
    (re.compile(r"/etc/cron|/var/spool/cron"), ("T1053.003",)),
    (re.compile(r"authorized_keys"), ("T1098.004",)),
    (re.compile(r"systemctl\s+enable|/etc/systemd/system"), ("T1543.002",)),
    (re.compile(r"/etc/rc\.local|/etc/init\.d/"), ("T1037.004",)),
    (re.compile(r"\.bashrc|\.bash_profile|/etc/profile"), ("T1546.004",)),
    (re.compile(r"base64\s+(?:-d|--decode)"), ("T1140",)),
    (re.compile(r"chmod\s+(?:\+x|[0-7]*7[0-7]{2})"), ("T1222.002",)),
    (re.compile(r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0|HISTFILE=/dev/null|\.bash_history\s*$|>\s*~?/?\S*\.bash_history"), ("T1070.003",)),
    (re.compile(r"(?:rm|shred|truncate|>)\s+(?:-\S+\s+)*/var/log|journalctl\s+--vacuum"), ("T1070.002",)),
    (re.compile(r"xmrig|minerd|stratum\+tcp|cryptonight|c3pool|supportxmr|nanopool|nicehash", re.I), ("T1496",)),
    (re.compile(r"(?:^|[\s/])\.env\b|\.aws/credentials|\.git-credentials|\.netrc|\.pgpass|wp-config\.php"), ("T1552.001",)),
    (re.compile(r"id_rsa|id_ed25519|id_ecdsa|\.ssh/"), ("T1552.004",)),
    (re.compile(r"cat\s+\S*\.bash_history|cat\s+~/\.\S*history"), ("T1552.003",)),
    (re.compile(r"\b(?:ba|da|z)?sh\s+-c\b|\|\s*(?:ba|da|z)?sh\b|(?:^|[;&|]\s*)\./\S+"), ("T1059.004",)),
    (re.compile(r"\b(?:python3?|perl)\s+-c\b"), ("T1059.006",)),
    (re.compile(r"(?:pkill|killall|kill\s+-9)"), ("T1489",)),
]


def map_command(line: str) -> list[str]:
    """sorted unique att&ck ids for one input line."""
    ids: set[str] = set()
    for seg in segments(line):
        ids.update(BY_COMMAND.get(command_name(seg), ()))
    for pat, tids in BY_PATTERN:
        if pat.search(line or ""):
            ids.update(tids)
    return sorted(ids)
