"""explainable bot | human | agent classifier.

every signal is a small function that returns Signal(label, weight, reason).
tune by editing WEIGHTS and the thresholds below; tests pin the behavior.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass

from .commands import COMMON, command_name, segments
from .session import Session

WEIGHTS = {
    # timing between commands
    "timing_clockwork": 3.0,   # fast and regular
    "timing_fast": 1.5,        # fast, not regular
    "timing_steady": 2.5,      # steady multi-second pauses
    "timing_irregular": 2.5,   # bursty, idle spikes
    # what they type
    "bot_script": 3.0,
    "semicolon_chain": 1.5,
    "typos": 2.5,
    "interactive_tools": 1.5,
    "wandering": 1.0,
    "reads_docs": 2.0,
    "readable_chains": 1.5,
    "follows_text": 2.5,
    "tripwire": 4.0,
    # ssh client string
    "client_bot": 1.5,
    "client_library": 0.75,      # split bot / agent
    "client_interactive": 0.75,  # split human / agent
    # login attempts
    "login_spray": 2.0,
    "dictionary_users": 1.0,
    "first_try_login": 0.5,      # split human / agent
    # network owner
    "asn_cloud": 1.0,
    "asn_scanner": 1.5,
}

# signals that count for two labels at once
SHARED_KEYS = {"client_library", "client_interactive", "first_try_login"}

# how much total weight before confidence stops being scaled down
MIN_EVIDENCE = 6.0
# emit a classified event when confidence moves at least this much
EMIT_CONF_DELTA = 0.15
MAX_CONFIDENCE = 0.99

# timing thresholds (seconds, coefficient of variation)
FAST_MEDIAN_S = 1.0
CLOCKWORK_CV = 0.5
STEADY_MEDIAN_S = (1.5, 25.0)
STEADY_CV = 0.6
IRREGULAR_CV = 0.8

# login-only scans: scripted client, no commands, gone within a few seconds
QUICK_SCAN_S = 5.0
QUICK_SCAN_CONF = 0.7


@dataclass(frozen=True)
class Signal:
    label: str
    key: str
    reason: str

    @property
    def weight(self) -> float:
        return WEIGHTS[self.key]


@dataclass(frozen=True)
class Verdict:
    kind: str
    confidence: float
    reasons: list[str]


# known bot script fingerprints: (pattern over all inputs joined by ";", name)
BOT_SCRIPTS = [
    (re.compile(r"\benable\b[;\s]+system\b[;\s]+shell\b"), "mirai login dance"),
    (re.compile(r"cd\s+/(?:tmp|var/run|mnt|dev/shm).*(?:wget|curl|tftp|ftpget).*(?:chmod|\bsh\s|\./)"), "tmp dropper"),
    (re.compile(r"echo\s+-e\s+['\"]?\\+x[0-9a-fA-F]{2}"), "hex echo probe"),
    (re.compile(r"/ip\s+cloud\s+print"), "mikrotik probe"),
    (re.compile(r"cat\s+/proc/cpuinfo\s*\|\s*grep\s+name\s*\|\s*wc\s+-l"), "cpu count probe"),
    (re.compile(r"uname\s+-s\s+-v\s+-n\s+-r\s+-m"), "uname probe"),
    (re.compile(r"rm\s+-rf\s+\.ssh\s*&&\s*mkdir\s+\.ssh"), "ssh key implant"),
    (re.compile(r"echo\s+['\"]?root:\S+?['\"]?\s*\|\s*chpasswd"), "root password swap"),
    (re.compile(r"ls\s+-lh\s+\$\(which\s+ls\)"), "ls probe"),
    (re.compile(r"crontab\s+-r\b"), "cron wipe"),
]

BOT_CLIENTS = re.compile(r"\bgo\b|libssh|jsch|zgrab|nmap|masscan|sshlib|dropbear_20(?:1[0-5])", re.I)
LIB_CLIENTS = re.compile(r"paramiko|asyncssh|twisted|russh|ssh2-js|node|phpseclib|sshj|net::ssh", re.I)
INTERACTIVE_CLIENTS = re.compile(r"openssh|putty|termius|securecrt|mobaxterm|bitvise|winscp", re.I)

DICTIONARY_USERS = {"root", "admin", "ubnt", "pi", "oracle", "test", "user", "support", "guest",
                    "ftp", "postgres", "mysql", "git", "ubuntu", "administrator", "default",
                    "nagios", "hadoop", "deploy", "www", "www-data", "debian", "centos", "usuario"}

TYPO_TARGETS = ["ls", "cd", "cat", "whoami", "uname", "pwd", "clear", "exit", "sudo", "grep",
                "ps", "top", "nano", "vim", "echo", "history", "mkdir", "cp", "mv", "rm",
                "ifconfig", "netstat", "wget", "curl", "chmod", "find", "less", "tail", "head",
                "hostname", "passwd"]
INTERACTIVE_TOOLS = {"clear", "vi", "vim", "nano", "emacs", "top", "htop", "less", "more", "watch"}
DOC_READERS = {"cat", "head", "less", "more", "tail", "bat", "nl"}
DOC_FILE = re.compile(r"readme|\.md\b|notes|todo|instructions|changelog|\.txt\b|/docs?/", re.I)
HELP_FLAG = re.compile(r"(?:^|\s)(?:--help|-h)(?:\s|$)")
TEXT_TOKEN = re.compile(r"(?:~|\.{0,2})?/[\w.\-/]+|\b[\w\-]+\.(?:sh|py|txt|env|md|conf|json|ya?ml|cfg|key|pem)\b")


def _osa(a: str, b: str) -> int:
    """edit distance with adjacent swaps."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _typo(token: str) -> bool:
    if not token or token in COMMON or "/" in token or len(token) < 2:
        return False
    if re.fullmatch(r"(?:cd|ls)[.\-/]\S*", token):
        return True
    return any(_osa(token, t) == 1 for t in TYPO_TARGETS)


# ---- signals ----

def timing_signals(s: Session) -> list[Signal]:
    ts = [c["ts"] for c in s.commands]
    if len(ts) < 3:
        return []
    gaps = [max(0.0, b - a) for a, b in zip(ts, ts[1:])]
    med = statistics.median(gaps)
    mean = statistics.fmean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean > 0 else 0.0
    if med < FAST_MEDIAN_S:
        if cv < CLOCKWORK_CV:
            return [Signal("bot", "timing_clockwork", f"commands every {med:.2f}s like clockwork")]
        return [Signal("bot", "timing_fast", "sub-second gaps between commands")]
    if cv >= IRREGULAR_CV:
        return [Signal("human", "timing_irregular", "irregular pauses between commands")]
    if STEADY_MEDIAN_S[0] <= med <= STEADY_MEDIAN_S[1] and cv < STEADY_CV:
        return [Signal("agent", "timing_steady", f"steady ~{med:.0f}s pauses, like waiting on a model")]
    return []


def content_signals(s: Session) -> list[Signal]:
    out: list[Signal] = []
    inputs = [c["input"] for c in s.commands]
    if not inputs:
        return out
    joined = ";".join(inputs)

    # bot: fixed scripts and long ; chains
    for pat, name in BOT_SCRIPTS:
        if pat.search(joined):
            out.append(Signal("bot", "bot_script", f"runs a known bot script ({name})"))
            break
    if any(line.count(";") >= 3 for line in inputs):
        out.append(Signal("bot", "semicolon_chain", "long ; chained one-liners"))

    # human: typos, backspaces, interactive tools, wandering
    names = [command_name(seg) for line in inputs for seg in segments(line)]
    typo = next((n for n in names if _typo(n)), None)
    if any(ch in line for line in inputs for ch in ("\x7f", "\x08")):
        out.append(Signal("human", "typos", "backspaces in typed commands"))
    elif typo:
        out.append(Signal("human", "typos", f"typos like '{typo}'"))
    if any(n in INTERACTIVE_TOOLS for n in names):
        tool = next(n for n in names if n in INTERACTIVE_TOOLS)
        out.append(Signal("human", "interactive_tools", f"uses interactive tools ({tool})"))
    if names.count("cd") >= 2 and names.count("ls") >= 2:
        out.append(Signal("human", "wandering", "wanders around with cd and ls"))

    # agent: reads docs, readable && chains, follows text it read
    if _reads_docs(inputs):
        out.append(Signal("agent", "reads_docs", "reads READMEs and help text"))
    if sum(1 for line in inputs if "&&" in line and ";" not in line) >= 2:
        out.append(Signal("agent", "readable_chains", "chains readable commands with &&"))
    if _follows_text(s.commands):
        out.append(Signal("agent", "follows_text", "follows instructions found in files"))
    return out


def _reads_docs(inputs: list[str]) -> bool:
    for line in inputs:
        for seg in segments(line):
            name = command_name(seg)
            if name == "man" or HELP_FLAG.search(seg):
                return True
            if name in DOC_READERS and DOC_FILE.search(seg):
                return True
    return False


def _is_doc_read(line: str) -> bool:
    return _reads_docs([line])


def _follows_text(commands: list[dict]) -> bool:
    """a later command uses a path that first showed up in docs it read."""
    learned: set[str] = set()
    typed: set[str] = set()
    for c in commands:
        line = c["input"]
        used = set(TEXT_TOKEN.findall(line))
        if used & (learned - typed):
            return True
        typed |= used
        if _is_doc_read(line):
            learned |= set(TEXT_TOKEN.findall(c.get("output", ""))) - used
    return False


def client_signals(s: Session) -> list[Signal]:
    c = s.client or ""
    if not c:
        return []
    short = c.replace("SSH-2.0-", "")[:40]
    if BOT_CLIENTS.search(short):
        return [Signal("bot", "client_bot", f"bot ssh client ({short})")]
    if LIB_CLIENTS.search(short):
        r = f"scripted ssh library ({short})"
        return [Signal("bot", "client_library", r), Signal("agent", "client_library", r)]
    if INTERACTIVE_CLIENTS.search(short):
        r = f"interactive ssh client ({short})"
        return [Signal("human", "client_interactive", r), Signal("agent", "client_interactive", r)]
    return []


def login_signals(s: Session) -> list[Signal]:
    out: list[Signal] = []
    fails = [x for x in s.logins if not x["success"]]
    if len(fails) >= 3:
        ts = [x["ts"] for x in fails]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        if gaps and statistics.median(gaps) < 2.0:
            out.append(Signal("bot", "login_spray", f"{len(fails)} rapid failed logins"))
    users = list(dict.fromkeys(x["username"] for x in s.logins))
    dict_users = [u for u in users if u.lower() in DICTIONARY_USERS]
    if len(dict_users) >= 3:
        out.append(Signal("bot", "dictionary_users", f"tries dictionary usernames ({', '.join(dict_users[:3])})"))
    if s.logins and s.logins[0]["success"]:
        r = "logged in on the first try"
        out += [Signal("human", "first_try_login", r), Signal("agent", "first_try_login", r)]
    return out


def quick_scan(s: Session) -> Verdict | None:
    """a scripted client that tried a few logins, ran nothing and left fast."""
    if not s.ended or s.commands or s.tripwires or not s.logins:
        return None
    short = (s.client or "").replace("SSH-2.0-", "")[:40]
    if not (BOT_CLIENTS.search(short) or LIB_CLIENTS.search(short)):
        return None
    took = (s.last_ts or 0.0) - (s.started_at or 0.0)
    if took > QUICK_SCAN_S:
        return None
    n = len(s.logins)
    when = "under a second" if took < 1 else f"{took:.1f}s"
    reasons = [f"scanner SSH client ({short})", f"tried {n} login{'s' if n > 1 else ''} in {when}, then left"]
    reasons += [x.reason for x in asn_signals(s)]
    return Verdict("bot", QUICK_SCAN_CONF, reasons)


def tripwire_signals(s: Session) -> list[Signal]:
    if not s.tripwires:
        return []
    n = len(s.tripwires)
    first = s.tripwires[0]
    why = (first.get("reasons") or [first.get("id", "tripwire")])[0]
    return [Signal("agent", "tripwire", f"tripped {n} tripwire{'s' if n > 1 else ''}: {why}"[:120])]


def asn_signals(s: Session) -> list[Signal]:
    org = (s.asn_org or "")[:40]
    if s.asn_category == "scanner":
        return [Signal("bot", "asn_scanner", f"known research scanner network ({org})")]
    if s.asn_category == "cloud":
        return [Signal("bot", "asn_cloud", f"comes from a hosting network ({org})")]
    return []


SIGNALS = (timing_signals, content_signals, client_signals, login_signals, tripwire_signals, asn_signals)


def signals(s: Session) -> list[Signal]:
    out: list[Signal] = []
    for fn in SIGNALS:
        out += fn(s)
    return out


UNKNOWN = Verdict("unknown", 0.0, ["not enough activity yet"])


def score(s: Session) -> Verdict:
    v = _weighed(s)
    quick = quick_scan(s)
    # a quick scan beats too little evidence or a weaker bot verdict
    if quick and (v.kind == "unknown" or (v.kind == "bot" and v.confidence < quick.confidence)):
        return quick
    return v


def _weighed(s: Session) -> Verdict:
    has_activity = bool(s.commands) or bool(s.tripwires) or len(s.logins) >= 3
    if not has_activity:
        return UNKNOWN
    sigs = signals(s)
    totals: dict[str, float] = {"bot": 0.0, "human": 0.0, "agent": 0.0}
    for sig in sigs:
        totals[sig.label] += sig.weight
    total = sum(totals.values())
    if total <= 0:
        return UNKNOWN
    # ties go to the order bot, human, agent
    winner = max(totals, key=lambda k: totals[k])
    support = sorted((x for x in sigs if x.label == winner), key=lambda x: -x.weight)
    # shared signals only break ties; the winner needs one of its own
    if len(support) < 2 or all(x.key in SHARED_KEYS for x in support):
        return UNKNOWN
    share = totals[winner] / total
    evidence = min(1.0, total / MIN_EVIDENCE)
    conf = round(min(MAX_CONFIDENCE, share * evidence), 2)
    reasons = list(dict.fromkeys(x.reason for x in support))[:4]
    return Verdict(winner, conf, reasons)


def should_emit(prev_kind: str, prev_conf: float, new: Verdict) -> bool:
    if new.kind != prev_kind:
        return True
    return abs(new.confidence - prev_conf) >= EMIT_CONF_DELTA
