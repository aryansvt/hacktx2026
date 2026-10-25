"""text commands: echo printf head tail wc sort uniq grep base64."""

from __future__ import annotations

import base64 as b64
import binascii

from ..engine import Ctx, Result, command
from ._util import BadPattern, compile_pattern, join_lines, parse_flags, read_inputs, rx_search, split_lines

SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "\\": "\\", "r": "\r"}


def unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in SIMPLE_ESCAPES:
            out.append(SIMPLE_ESCAPES[s[i + 1]])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


@command("echo")
def echo(ctx: Ctx, args: list[str]) -> Result:
    newline, escapes = True, False
    while args and args[0] in ("-n", "-e", "-E", "-ne", "-en"):
        flag = args.pop(0)
        newline = newline and "n" not in flag
        escapes = "e" in flag
    text = " ".join(args)
    if escapes:
        text = unescape(text)
    return Result(text + ("\n" if newline else ""))


@command("printf")
def printf(ctx: Ctx, args: list[str]) -> Result:
    if not args:
        return Result(err="printf: usage: printf [-v var] format [arguments]\n", code=2)
    fmt, values = unescape(args[0]), list(args[1:])
    out = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == "%" and i + 1 < len(fmt):
            spec = fmt[i + 1]
            if spec == "%":
                out.append("%")
            elif spec == "s":
                out.append(values.pop(0) if values else "")
            elif spec in "di":
                v = values.pop(0) if values else "0"
                out.append(v if v.lstrip("-").isdigit() else "0")
            else:
                out.append(c + spec)
            i += 2
        else:
            out.append(c)
            i += 1
    return Result("".join(out))


def _count_flag(flags: dict, args_default: int = 10) -> int:
    for key in ("n", "lines"):
        v = flags.get(key)
        if isinstance(v, str) and v.lstrip("+-").isdigit():
            return int(v.lstrip("+"))
    return args_default


def _numeric_shorthand(args: list[str]) -> list[str]:
    # head -5 means head -n 5
    return [("-n" + a[1:]) if a[:1] == "-" and a[1:].isdigit() else a for a in args]


@command("head")
def head(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(_numeric_shorthand(args), with_value="nc")
    items, err, code = read_inputs(ctx, files)
    n = _count_flag(flags)
    out = []
    for idx, (name, text) in enumerate(items):
        if len(items) > 1:
            out.append(("\n" if idx else "") + f"==> {name} <==\n")
        if isinstance(flags.get("c"), str) and flags["c"].isdigit():
            out.append(text[: int(flags["c"])])
            continue
        lines = split_lines(text)
        out.append(join_lines(lines[:n]))
    return Result("".join(out), err, code)


@command("tail")
def tail(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(_numeric_shorthand(args), with_value="nc")
    items, err, code = read_inputs(ctx, files)
    n = abs(_count_flag(flags))
    out = []
    for idx, (name, text) in enumerate(items):
        if len(items) > 1:
            out.append(("\n" if idx else "") + f"==> {name} <==\n")
        lines = split_lines(text)
        out.append(join_lines(lines[-n:] if n else []))
    return Result("".join(out), err, code)


@command("wc")
def wc(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args)
    items, err, code = read_inputs(ctx, files)
    picked = [k for k in ("l", "w", "c") if flags.get(k)] or ["l", "w", "c"]
    rows = []
    totals = {"l": 0, "w": 0, "c": 0}
    for name, text in items:
        counts = {"l": text.count("\n"), "w": len(text.split()), "c": len(text.encode())}
        for k in totals:
            totals[k] += counts[k]
        rows.append(([counts[k] for k in picked], "" if name == "-" else name))
    if len(items) > 1:
        rows.append(([totals[k] for k in picked], "total"))
    if len(rows) == 1 and len(picked) == 1:
        nums, name = rows[0]
        return Result(f"{nums[0]} {name}".rstrip() + "\n", err, code)
    width = max(len(str(n)) for nums, _ in rows for n in nums)
    if any(name == "" for _, name in rows):
        width = max(width, 7)
    out = "".join(" ".join(f"{n:>{width}}" for n in nums) + (f" {name}" if name else "") + "\n" for nums, name in rows)
    return Result(out, err, code)


@command("sort")
def sort(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args, with_value="kt")
    items, err, code = read_inputs(ctx, files)
    lines = [l for _, text in items for l in split_lines(text)]

    def key(line: str):
        field = line
        if isinstance(flags.get("k"), str) and flags["k"].split(",")[0].isdigit():
            parts = line.split(flags["t"]) if isinstance(flags.get("t"), str) and flags["t"] else line.split()
            k = int(flags["k"].split(",")[0]) - 1
            field = parts[k] if k < len(parts) else ""
        if flags.get("n"):
            head = ""
            for ch in field.strip():
                if ch.isdigit() or (ch in "-." and not head):
                    head += ch
                else:
                    break
            try:
                return (float(head), line)
            except ValueError:
                return (0.0, line)
        return (field.lower() if flags.get("f") else field, line)

    lines.sort(key=key, reverse=bool(flags.get("r")))
    if flags.get("u"):
        seen, uniq_lines = set(), []
        for l in lines:
            if l not in seen:
                seen.add(l)
                uniq_lines.append(l)
        lines = uniq_lines
    return Result(join_lines(lines), err, code)


@command("uniq")
def uniq(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args)
    items, err, code = read_inputs(ctx, files[:1])
    groups: list[list] = []
    for line in split_lines(items[0][1] if items else ""):
        if groups and groups[-1][0] == line:
            groups[-1][1] += 1
        else:
            groups.append([line, 1])
    if flags.get("d"):
        groups = [g for g in groups if g[1] > 1]
    if flags.get("u"):
        groups = [g for g in groups if g[1] == 1]
    if flags.get("c"):
        return Result("".join(f"{n:>7} {l}\n" for l, n in groups), err, code)
    return Result(join_lines([l for l, _ in groups]), err, code)


@command("grep", "egrep", "fgrep")
def grep(ctx: Ctx, args: list[str]) -> Result:
    flags, pos = parse_flags(args, with_value="emA")
    pattern = flags.get("e") if isinstance(flags.get("e"), str) else (pos.pop(0) if pos else None)
    if pattern is None:
        return Result(err="Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", code=2)
    try:
        rx = compile_pattern(
            pattern,
            ere=bool(flags.get("E")) or ctx.name == "egrep",
            fixed=bool(flags.get("F")) or ctx.name == "fgrep",
            icase=bool(flags.get("i")),
            word=bool(flags.get("w")),
        )
    except BadPattern:
        return Result(err="grep: Unmatched ( or \\(\n", code=2)
    files = pos
    if (flags.get("r") or flags.get("R")) and files:
        expanded = []
        for f in files:
            for full, node in ctx.fs.walk(ctx.path(f), ctx.user):
                if node.type == "file":
                    expanded.append(full)
        files = expanded
    items, err, code = read_inputs(ctx, files)
    show_name = (len(items) > 1 or flags.get("r") or flags.get("R")) and not flags.get("h")
    out = []
    total = 0
    for name, text in items:
        count = 0
        for num, line in enumerate(split_lines(text), 1):
            hit = rx_search(rx, line) is not None
            if hit == bool(flags.get("v")):
                continue
            count += 1
            if flags.get("c") or flags.get("l") or flags.get("q"):
                continue
            prefix = (f"{name}:" if show_name else "") + (f"{num}:" if flags.get("n") else "")
            out.append(prefix + line + "\n")
        total += count
        if flags.get("c"):
            out.append((f"{name}:" if show_name else "") + f"{count}\n")
        elif flags.get("l") and count:
            out.append(name + "\n")
    if flags.get("q"):
        out = []
    if flags.get("s"):
        err = ""
    if code:
        return Result("".join(out), err, 2)
    return Result("".join(out), err, 0 if total else 1)


@command("base64")
def base64_cmd(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args, with_value="w")
    items, err, code = read_inputs(ctx, files[:1])
    text = items[0][1] if items else ""
    if flags.get("d") or flags.get("decode"):
        try:
            data = b64.b64decode("".join(text.split()), validate=True)
        except (binascii.Error, ValueError):
            return Result(err="base64: invalid input\n", code=1)
        return Result(data.decode("utf-8", errors="replace"), err, code)
    encoded = b64.b64encode(text.encode()).decode()
    if flags.get("w") == "0":
        return Result(encoded, err, code)
    return Result(join_lines([encoded[i : i + 76] for i in range(0, len(encoded), 76)]), err, code)
