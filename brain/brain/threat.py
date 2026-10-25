"""threat ladder: low < med < high < critical. it only goes up."""

from __future__ import annotations

import re

from .commands import downloaded_files, executed_files, is_download, pipes_to_shell

LEVELS = ("low", "med", "high", "critical")

CRED_RE = re.compile(
    r"/etc/shadow|(?:^|[\s/])\.env\b|\.aws/credentials|\.git-credentials|\.netrc|\.pgpass|"
    r"id_rsa|id_ed25519|id_ecdsa|\.bash_history|wp-config\.php|wallet\.dat|\.docker/config\.json|"
    r"\.kube/config|credentials\.json"
)
PERSIST_RE = re.compile(
    r"crontab\s+(?!-l\b)|/etc/cron|/var/spool/cron|authorized_keys|\buseradd\b|\badduser\b|"
    r"\busermod\b|\bchpasswd\b|systemctl\s+enable|/etc/rc\.local|/etc/init\.d/|/etc/systemd/system|"
    r">>?\s*~?/?\S*\.bashrc|\bchattr\s+\+i"
)
MINER_RE = re.compile(
    r"xmrig|minerd|cpuminer|stratum\+tcp|cryptonight|c3pool|supportxmr|nanopool|nicehash|"
    r"kdevtmpfsi|kinsing|\bmonero\b|--donate-level",
    re.I,
)
WIPE_RE = re.compile(
    r"(?:rm|shred|truncate)\s+(?:-\S+\s+)*\S*/var/log|>\s*/var/log/|history\s+-c|unset\s+HISTFILE|"
    r"HISTSIZE=0|HISTFILE=/dev/null|journalctl\s+--vacuum|(?:rm|shred)\s+(?:-\S+\s+)*\S*\.bash_history|"
    r"ln\s+-sf?\s+/dev/null\s+\S*history"
)


def rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else 0


def max_level(*levels: str) -> str:
    return LEVELS[max(rank(lv) for lv in levels)]


def bump(level: str) -> str:
    return LEVELS[min(rank(level) + 1, len(LEVELS) - 1)]


def runs_payload(line: str, downloads: list[str]) -> bool:
    """true when the line runs something downloaded, here or earlier."""
    if pipes_to_shell(line) and (is_download(line) or "base64" in line):
        return True
    known = set(downloads) | set(downloaded_files(line))
    return any(f in known for f in executed_files(line))


def level_for_command(line: str, downloads: list[str]) -> str:
    if MINER_RE.search(line) or WIPE_RE.search(line) or runs_payload(line, downloads):
        return "critical"
    if CRED_RE.search(line) or PERSIST_RE.search(line) or is_download(line):
        return "high"
    return "low"


def level_for_event(event_type: str, line: str = "", downloads: list[str] | None = None) -> str:
    """base level one raw event earns on its own."""
    if event_type == "login_success":
        return "med"
    if event_type == "command":
        # anyone running commands is inside, so at least med
        return max_level("med", level_for_command(line, downloads or []))
    return "low"


def apply(stored: str, base: str, reputation: str) -> str:
    """new threat given the stored value, the highest base seen and reputation."""
    effective = bump(base) if reputation == "malicious" else base
    return max_level(stored or "low", effective)
