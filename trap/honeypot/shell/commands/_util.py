"""helpers shared by command modules."""

from __future__ import annotations

import math
import time
from datetime import datetime, timezone

import regex

from ...vfs import FsError, Node
from ..engine import Ctx

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
REGEX_TIMEOUT = 0.05  # seconds per match call, stops catastrophic patterns
MAX_PATTERN = 300


def parse_flags(args: list[str], with_value: str = "", long_value: tuple[str, ...] = ()) -> tuple[dict, list[str]]:
    """getopt-ish. returns ({flag: value or True}, positionals)."""
    flags: dict = {}
    pos: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos.extend(args[i + 1 :])
            break
        if a.startswith("--") and len(a) > 2:
            key, eq, val = a[2:].partition("=")
            if eq:
                flags[key] = val
            elif key in long_value and i + 1 < len(args):
                flags[key] = args[i + 1]
                i += 1
            else:
                flags[key] = True
        elif a.startswith("-") and len(a) > 1 and not a[1:].lstrip("-").isdigit():
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in with_value:
                    rest = a[j + 1 :]
                    if rest:
                        flags[ch] = rest
                    elif i + 1 < len(args):
                        flags[ch] = args[i + 1]
                        i += 1
                    else:
                        flags[ch] = ""
                    break
                flags[ch] = True
                j += 1
        else:
            pos.append(a)
        i += 1
    return flags, pos


def now() -> datetime:
    return datetime.now(timezone.utc)


def boot_time(ctx: Ctx) -> datetime:
    return datetime.strptime(ctx.system["boot_time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def uptime_seconds(ctx: Ctx) -> float:
    return max(60.0, (now() - boot_time(ctx)).total_seconds())


def load_avg() -> tuple[float, float, float]:
    # small, slowly drifting numbers so repeated calls look alive
    t = time.time()
    a = 0.05 + 0.04 * (1 + math.sin(t / 97))
    return round(a, 2), round(a * 0.7 + 0.01, 2), round(a * 0.4 + 0.01, 2)


def dynamic(ctx: Ctx, path: str) -> str | None:
    if path == "/proc/uptime":
        up = uptime_seconds(ctx)
        return f"{up:.2f} {up * 1.93:.2f}\n"
    if path == "/proc/loadavg":
        a, b, c = load_avg()
        return f"{a:.2f} {b:.2f} {c:.2f} 1/214 {ctx.state.pid + 3}\n"
    return None


def read_file(ctx: Ctx, path: str) -> str:
    real = ctx.fs.realpath(ctx.path(path))
    dyn = dynamic(ctx, real)
    if dyn is not None:
        return dyn
    return ctx.fs.read(real, ctx.user)


def read_inputs(ctx: Ctx, files: list[str]) -> tuple[list[tuple[str, str]], str, int]:
    """[(name, text)], error text, exit code. no files means stdin."""
    if not files or files == ["-"]:
        return [("-", ctx.stdin or "")], "", 0
    out, errs, code = [], [], 0
    for f in files:
        if f == "-":
            out.append(("-", ctx.stdin or ""))
            continue
        try:
            out.append((f, read_file(ctx, f)))
        except FsError as e:
            errs.append(f"{ctx.name}: {f}: {e.message}\n")
            code = 1
    return out, "".join(errs), code


def mode_str(node: Node) -> str:
    kind = {"dir": "d", "link": "l", "file": "-"}[node.type]
    m = node.mode
    out = [kind]
    for shift, special, ch in ((6, 0o4000, "s"), (3, 0o2000, "s"), (0, 0o1000, "t")):
        r = "r" if m & (4 << shift) else "-"
        w = "w" if m & (2 << shift) else "-"
        x = bool(m & (1 << shift))
        if m & special:
            xc = ch if x else ch.upper()
        else:
            xc = "x" if x else "-"
        out += [r, w, xc]
    return "".join(out)


def ls_time(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, timezone.utc)
    if abs((now() - dt).days) < 180:
        return f"{MONTHS[dt.month - 1]} {dt.day:>2} {dt.hour:02d}:{dt.minute:02d}"
    return f"{MONTHS[dt.month - 1]} {dt.day:>2}  {dt.year}"


def ctime(dt: datetime) -> str:
    return f"{DAYS[dt.weekday()]} {MONTHS[dt.month - 1]} {dt.day:>2} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} UTC {dt.year}"


def human(n: float, suffix_bytes: bool = False) -> str:
    if n < 1024:
        return f"{int(n)}{'B' if suffix_bytes else ''}"
    for unit in "KMGTP":
        n /= 1024
        if n < 1024 or unit == "P":
            if n < 10:
                return f"{math.ceil(n * 10) / 10:.1f}{unit}"
            return f"{math.ceil(n)}{unit}"
    return str(n)


def columns(names: list[str], width: int = 80) -> str:
    if not names:
        return ""
    n = len(names)
    for cols in range(min(n, width // 3) or 1, 0, -1):
        rows = math.ceil(n / cols)
        widths = []
        for c in range(cols):
            chunk = names[c * rows : (c + 1) * rows]
            if chunk:
                widths.append(max(len(x) for x in chunk) + 2)
        if sum(widths) - 2 <= width or cols == 1:
            lines = []
            for r in range(rows):
                parts = []
                for c in range(len(widths)):
                    k = c * rows + r
                    if k < n:
                        last = c == len(widths) - 1 or (c + 1) * rows + r >= n
                        parts.append(names[k] if last else names[k].ljust(widths[c]))
                lines.append("".join(parts))
            return "\n".join(lines) + "\n"
    return "\n".join(names) + "\n"


def bre_to_ere(pat: str) -> str:
    """posix basic regex to the extended form the regex module understands."""
    out = []
    i = 0
    in_bracket = False
    while i < len(pat):
        c = pat[i]
        if in_bracket:
            out.append(c)
            if c == "]" and not (out[-2:-1] == ["["] or out[-3:-1] == ["[", "^"]):
                in_bracket = False
        elif c == "[":
            in_bracket = True
            out.append(c)
        elif c == "\\" and i + 1 < len(pat):
            nxt = pat[i + 1]
            out.append(nxt if nxt in "(){}|+?" else c + nxt)
            i += 1
        elif c in "(){}|+?":
            out.append("\\" + c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


class BadPattern(Exception):
    pass


def compile_pattern(pat: str, ere: bool = False, fixed: bool = False, icase: bool = False, word: bool = False):
    if len(pat) > MAX_PATTERN:
        raise BadPattern("pattern too long")
    if fixed:
        body = regex.escape(pat)
    else:
        body = pat if ere else bre_to_ere(pat)
    if word:
        body = rf"\b(?:{body})\b"
    try:
        return regex.compile(body, regex.IGNORECASE if icase else 0)
    except regex.error as e:
        raise BadPattern(str(e)) from None


def rx_search(rx, line: str):
    try:
        return rx.search(line[:4096], timeout=REGEX_TIMEOUT)
    except TimeoutError:
        return None


def rx_sub(rx, repl, line: str, count: int = 0) -> str:
    try:
        return rx.sub(repl, line[:4096], count=count, timeout=REGEX_TIMEOUT)
    except TimeoutError:
        return line


def split_lines(text: str) -> list[str]:
    """lines without the trailing empty piece."""
    if not text:
        return []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def join_lines(lines: list[str]) -> str:
    return "".join(l + "\n" for l in lines)


def uid_of(ctx: Ctx, user: str) -> tuple[int, int]:
    entry = ctx.state.passwd_entry(user)
    if entry:
        return int(entry[2]), int(entry[3])
    return 1100, 1100


def groups_of(ctx: Ctx, user: str) -> list[tuple[str, int]]:
    uid, gid = uid_of(ctx, user)
    primary = None
    extra = []
    try:
        text = ctx.fs.read("/etc/group")
    except FsError:
        text = ""
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        g = (parts[0], int(parts[2]))
        if int(parts[2]) == gid:
            primary = g
        elif user in parts[3].split(","):
            extra.append(g)
    return [primary or (user, gid)] + extra
