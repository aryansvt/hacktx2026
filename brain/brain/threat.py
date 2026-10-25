"""threat ladder: low < med < high < critical. it only goes up."""

from __future__ import annotations

import posixpath
import re

from .commands import (
    chmodded_executable,
    downloaded_files,
    executed_files,
    is_download,
    pipelines,
    pipes_to_shell,
    written_files,
)

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
# files whose writes are persistence (high), never a payload
PERSIST_FILE_RE = re.compile(
    r"cron|authorized_keys|rc\.local|/init\.d/|systemd|\.service$|\.timer$|\.bashrc$|\.(?:bash_)?profile$"
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


def payload_writes(line: str) -> list[str]:
    """names of files the line writes by hand, minus persistence targets."""
    return list(dict.fromkeys(posixpath.basename(p) for p in written_files(line) if not PERSIST_FILE_RE.search(p)))


def runs_payload(line: str, downloads: list[str], written: list[str] = ()) -> bool:
    """true when the line runs something downloaded, or runs or chmods +x something it wrote."""
    # the download and the | sh have to be in the same pipeline
    if any(pipes_to_shell(p) and (is_download(p) or "base64" in p) for p in pipelines(line)):
        return True
    known = set(downloads) | set(downloaded_files(line))
    if any(f in known for f in executed_files(line)):
        return True
    mine = set(written) | set(payload_writes(line))
    return any(f in mine for f in executed_files(line) + chmodded_executable(line))


def level_for_command(line: str, downloads: list[str], written: list[str] = ()) -> str:
    if MINER_RE.search(line) or WIPE_RE.search(line) or runs_payload(line, downloads, written):
        return "critical"
    if CRED_RE.search(line) or PERSIST_RE.search(line) or is_download(line) or writes_persistence(line):
        return "high"
    return "low"


def writes_persistence(line: str) -> bool:
    """writes by hand to a cron, rc.local, systemd or authorized_keys file, even by a relative path."""
    return any(PERSIST_FILE_RE.search(p) for p in written_files(line))


def level_for_event(event_type: str, line: str = "", downloads: list[str] | None = None,
                    written: list[str] | None = None) -> str:
    """base level one raw event earns on its own."""
    if event_type == "login_success":
        return "med"
    if event_type == "command":
        # anyone running commands is inside, so at least med
        return max_level("med", level_for_command(line, downloads or [], written or []))
    return "low"


def apply(stored: str, base: str, reputation: str) -> str:
    """new threat given the stored value, the highest base seen and reputation."""
    # malicious bumps one level, but only running something reaches critical
    effective = bump(base) if reputation == "malicious" and rank(base) < rank("high") else base
    return max_level(stored or "low", effective)
