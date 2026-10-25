"""pure helpers for reading attacker command lines. nothing here runs or fetches anything."""

from __future__ import annotations

import posixpath
import re
from urllib.parse import urlsplit

_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
URL_RE = re.compile(r"\b(?:https?|ftp|tftp)://[^\s\"'<>|;`)]+", re.I)
_BARE_HOST = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/\S*)?$", re.I)
_IPV4_HOST = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/\S*)?$")
_SHELL_PIPE = re.compile(r"\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:ba|da|z)?sh\b")
# quoted args (grep patterns, awk programs) except a shell's -c script or eval's text
_QUOTED_ARG = re.compile(r"""(?<!-c )(?<!eval )('[^']*'|"[^"]*")""")
_PIPELINES = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")

# file extensions that make a token a file name, not a host
_FILE_EXT = (".sh", ".txt", ".py", ".pl", ".conf", ".cfg", ".log", ".json", ".md",
             ".env", ".tar", ".gz", ".tgz", ".zip", ".bin", ".so", ".yml", ".yaml",
             ".ini", ".php", ".js", ".html", ".key", ".pem", ".db", ".sql", ".bak")

DOWNLOADERS = {"wget", "curl", "tftp", "ftpget", "scp", "lwp-download", "fetch", "aria2c"}
SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh"}

# binaries any linux box has. anything else counts as an unusual tool name
COMMON = {
    "ls", "cd", "pwd", "cat", "echo", "printf", "uname", "whoami", "id", "w", "who",
    "last", "lastlog", "hostname", "uptime", "ps", "top", "htop", "free", "df", "du",
    "mount", "lscpu", "nproc", "lsblk", "lspci", "lsusb", "dmesg", "ifconfig", "ip",
    "route", "netstat", "ss", "arp", "ping", "traceroute", "dig", "nslookup", "host",
    "wget", "curl", "tftp", "ftpget", "scp", "ssh", "sftp", "rsync", "nc", "ncat",
    "telnet", "chmod", "chown", "chattr", "lsattr", "rm", "mv", "cp", "mkdir", "rmdir",
    "touch", "ln", "find", "locate", "which", "whereis", "type", "file", "stat", "head",
    "tail", "less", "more", "grep", "egrep", "fgrep", "awk", "sed", "cut", "sort",
    "uniq", "wc", "tr", "xargs", "tee", "tar", "gzip", "gunzip", "zip", "unzip",
    "base64", "md5sum", "sha256sum", "xxd", "od", "strings", "env", "export", "set",
    "unset", "history", "alias", "clear", "exit", "logout", "sudo", "su", "passwd",
    "chpasswd", "useradd", "adduser", "userdel", "usermod", "groups", "crontab",
    "systemctl", "service", "journalctl", "kill", "pkill", "killall", "nohup",
    "sleep", "date", "cal", "man", "info", "help", "vi", "vim", "nano", "emacs",
    "python", "python3", "perl", "ruby", "php", "node", "java", "gcc", "make", "git",
    "apt", "apt-get", "yum", "dnf", "apk", "pip", "pip3", "npm", "docker", "kubectl",
    "iptables", "ufw", "shred", "truncate", "dd", "sync", "reboot", "shutdown",
    "halt", "busybox", "enable", "system", "shell", "sh", "bash", "dash", "zsh",
    "ash", "true", "false", "test", "lsof", "getconf", "locale", "tty", "stty",
    "mesg", "finger", "pgrep", "nice", "renice", "watch", "time", "bc", "expr",
    "seq", "yes", "basename", "dirname", "readlink", "realpath", "mktemp", "diff",
    "cmp", "patch", "openssl", "ssh-keygen", "lsmod", "modprobe", "sysctl", "ulimit",
    "source", ".", "exec", "eval", "read", "wait", "jobs", "fg", "bg", "disown",
    "cls", "dir", "ver", "tasklist", "ftp", "sshd", "init", "mail", "chsh", "visudo",
    "setsid", "screen", "tmux", "strace", "ltrace", "ldd", "ldconfig", "chroot", "mkfifo",
    "mknod", "insmod", "rmmod", "groupadd", "cron", "crond", "systemd", "udevadm", "ip6tables",
    "nft", "tcpdump", "nmap", "masscan", "zmap", "socat", "wall", "write", "base32",
}

# bash builtins not already in COMMON
BUILTINS = {
    "bind", "break", "builtin", "caller", "command", "compgen", "complete", "compopt",
    "continue", "declare", "dirs", "getopts", "hash", "let", "local", "mapfile", "popd",
    "pushd", "readarray", "readonly", "return", "shift", "shopt", "suspend", "times", "trap",
    "typeset", "umask", "unalias",
}

# everyday english words that turn up as file names and say nothing on a web search
ENGLISH_WORDS = {
    "filter", "update", "updates", "upgrade", "install", "installer", "setup", "config",
    "configure", "start", "stop", "restart", "script", "scripts", "main", "data", "file",
    "files", "check", "checker", "clean", "cleaner", "build", "server", "client", "service",
    "backup", "temp", "list", "index", "home", "user", "users", "admin", "root", "system",
    "network", "download", "upload", "payload", "agent", "loader", "runner", "launch",
    "launcher", "monitor", "worker", "manager", "helper", "tool", "tools", "test", "tests",
    "demo", "sample", "example", "hello", "world", "print", "output", "input", "result",
    "results", "report", "status", "debug", "error", "errors", "info", "help", "readme",
    "license", "notes", "todo", "note", "work", "job", "jobs", "task", "tasks", "cleanup",
    "deploy", "remove", "delete", "kill", "killer", "watch", "watchdog", "guard", "patch",
    "fix", "sync", "copy", "move", "send", "sender", "receive", "proxy", "socket", "connect",
    "bridge", "tunnel", "scan", "scanner", "crawl", "crawler", "spider", "bot", "bots",
    "brute", "force", "attack", "exploit", "shell", "shells", "door", "backdoor", "trojan",
    "virus", "malware", "miner", "mining", "crypto", "wallet", "pool", "web", "site", "page",
    "pages", "image", "images", "video", "audio", "music", "photo", "photos", "document",
    "documents", "local", "remote", "global", "public", "private", "secret", "secure",
    "security", "access", "login", "logout", "session", "token", "password", "passwords",
    "random", "simple", "basic", "default", "custom", "special", "standard", "normal",
    "final", "first", "last", "next", "previous", "new", "old", "latest", "current", "stable",
    "release", "version", "linux", "unix", "kernel", "boot", "power", "speed", "fast",
    "slow", "quick", "small", "large", "little", "big", "good", "best", "nice", "cool",
    "free", "open", "close", "read", "write", "load", "save", "store", "cache", "queue",
    "stack", "table", "tables", "time", "date", "clock", "timer", "count", "counter",
    "number", "value", "values", "string", "text", "word", "words", "name", "names",
    "path", "paths", "link", "links", "node", "nodes", "tree", "graph", "map", "maps",
    "game", "games", "play", "player", "chat", "message", "messages", "mail", "email",
}


def segments(line: str) -> list[str]:
    """split a line on ; && || | and newlines."""
    return [s for s in _SPLIT.split(line or "") if s.strip()]


def words(segment: str) -> list[str]:
    return segment.strip().split()


def command_name(segment: str) -> str:
    """first real command in a segment, skipping sudo, env vars, busybox and paths."""
    toks = words(segment)
    while toks and (posixpath.basename(toks[0]) in ("sudo", "nohup", "exec", "busybox", "time", "env")
                    or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0])):
        toks = toks[1:]
    if not toks:
        return ""
    t = toks[0]
    if t.startswith("./"):
        return t
    return posixpath.basename(t) if "/" in t else t


def urls(line: str) -> list[str]:
    return URL_RE.findall(line or "")


def _bare_hosts(line: str) -> list[str]:
    """host-looking args given to downloaders without a scheme, e.g. wget evil.com/x.sh"""
    out = []
    for seg in segments(line):
        if command_name(seg) not in DOWNLOADERS:
            continue
        for tok in words(seg)[1:]:
            if tok.startswith("-") or "://" in tok:
                continue
            if _IPV4_HOST.match(tok) or (_BARE_HOST.match(tok) and not tok.lower().endswith(_FILE_EXT)):
                out.append(tok)
    return out


def domains(line: str) -> list[str]:
    """hosts named in a line. strings only, never resolved."""
    hosts: list[str] = []
    for u in urls(line):
        h = urlsplit(u).hostname
        if h:
            hosts.append(h.lower())
    for tok in _bare_hosts(line):
        hosts.append(tok.split("/")[0].split(":")[0].lower())
    return list(dict.fromkeys(hosts))


def is_download(line: str) -> bool:
    for seg in segments(line):
        name = command_name(seg)
        if name not in DOWNLOADERS:
            continue
        rest = " ".join(words(seg)[1:])
        if name == "scp" and re.search(r"\S+@?\S+:\S*", rest):
            return True
        if name == "tftp" and re.search(r"\s-r\s|\s-g\b|-gr\b", " " + rest):
            return True
        if URL_RE.search(seg) or _bare_hosts(seg):
            return True
    return False


def downloaded_files(line: str) -> list[str]:
    """file names a download in this line would create."""
    if not is_download(line):
        return []
    names = []
    for seg in segments(line):
        if command_name(seg) not in DOWNLOADERS:
            continue
        toks = words(seg)
        for i, t in enumerate(toks):
            if t in ("-O", "-o", "-r", "--output") and i + 1 < len(toks) and toks[i + 1] != "-":
                names.append(posixpath.basename(toks[i + 1]))
        for u in URL_RE.findall(seg):
            base = posixpath.basename(urlsplit(u).path)
            if base:
                names.append(base)
        for h in _bare_hosts(seg):
            if "/" in h:
                base = posixpath.basename(h)
                if base:
                    names.append(base)
    return list(dict.fromkeys(n for n in names if n))


def executed_files(line: str) -> list[str]:
    """files the line tries to run: ./x, sh x, bash x, /tmp/x"""
    out = []
    for seg in segments(line):
        toks = words(seg)
        while toks and toks[0] in ("sudo", "nohup", "exec"):
            toks = toks[1:]
        if not toks:
            continue
        t = toks[0]
        if t.startswith("./") or t.startswith("/tmp/") or t.startswith("/dev/shm/") or t.startswith("/var/tmp/"):
            out.append(posixpath.basename(t))
        elif posixpath.basename(t) in SHELLS and len(toks) > 1 and not toks[1].startswith("-"):
            out.append(posixpath.basename(toks[1]))
    return [o for o in out if o]


# quoted strings match first so a > inside echo text isn't a redirect
_REDIRECT = re.compile(r"""'[^']*'|"[^"]*"|(?<![0-9&>])>>?\s*('[^']*'|"[^"]*"|[^\s;&|<>'"]+)""")
WRITERS = {"echo", "printf", "cat"}
_DECODE_FLAGS = {"-d", "--decode", "-D"}
_CHMOD_FLAG = re.compile(r"^(?:-[Rvfc]+|--[a-z-]+)$")


def _args(seg: str, name: str) -> list[str]:
    """words after the command itself, past any sudo or path prefix."""
    toks = words(seg)
    i = next((i for i, t in enumerate(toks) if posixpath.basename(t) == name), len(toks))
    return toks[i + 1:]


def written_files(line: str) -> list[str]:
    """paths a line writes by hand: echo/printf/cat/base64 -d with > or >>, or tee."""
    out = []
    for seg in segments(line):
        name = command_name(seg)
        if name == "tee":
            out += [t for t in _args(seg, "tee") if not t.startswith("-")]
        elif name in WRITERS or (name == "base64" and _DECODE_FLAGS & set(words(seg))):
            out += [m.group(1) for m in _REDIRECT.finditer(seg) if m.group(1)]
    paths = (p.strip("'\"") for p in out)
    return list(dict.fromkeys(p for p in paths if p and not p.startswith("/dev/")))


def _executable_mode(mode: str) -> bool:
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return any(int(d) & 1 for d in mode[-3:])
    return any(re.search(r"\+[rwxXst]*x", part) for part in mode.split(","))


def chmodded_executable(line: str) -> list[str]:
    """file names a line makes executable: chmod +x x, chmod 755 x"""
    out = []
    for seg in segments(line):
        if command_name(seg) != "chmod":
            continue
        args = [t for t in _args(seg, "chmod") if not _CHMOD_FLAG.match(t)]
        if len(args) >= 2 and _executable_mode(args[0]):
            out += [posixpath.basename(a) for a in args[1:]]
    return list(dict.fromkeys(o for o in out if o))


def pipes_to_shell(line: str) -> bool:
    """a real | sh, not one inside a quoted grep pattern."""
    return bool(_SHELL_PIPE.search(_QUOTED_ARG.sub("''", line or "")))


def pipelines(line: str) -> list[str]:
    """split a line on ; && || and newlines, keeping | pipes together."""
    return [p for p in _PIPELINES.split(line or "") if p.strip()]


def _distinctive(name: str) -> bool:
    """worth a web search: not a builtin, standard command, common word or tiny name."""
    stem = name.rsplit(".", 1)[0] if "." in name[1:] else name
    stem = stem.lstrip(".").lower()
    return (len(stem) >= 4 and stem not in COMMON and stem not in BUILTINS and stem not in ENGLISH_WORDS
            and bool(re.fullmatch(r"[a-z0-9_.-]+", stem)) and not stem.isdigit())


def tool_names(line: str) -> list[str]:
    """programs a line runs, chmods +x or downloads, with distinctive names, e.g. xmrig or kinsing."""
    names = executed_files(line) + chmodded_executable(line) + downloaded_files(line)
    return list(dict.fromkeys(n for n in names if _distinctive(n)))
