"""filesystem commands: ls cd pwd cat mkdir rm cp mv chmod find ..."""

from __future__ import annotations

import fnmatch
import posixpath
import shlex
from datetime import datetime, timezone

from ...vfs import FsError, Node
from ..engine import ELF_MAGIC, Ctx, Result, command
from ._util import columns, human, ls_time, mode_str, parse_flags, read_inputs, uid_of


# ls

def _ls_long(ctx: Ctx, entries: list[tuple[str, Node, str]], flags: dict) -> list[str]:
    rows = []
    for name, node, full in entries:
        links = 1
        if node.type == "dir":
            try:
                links = 2 + sum(1 for n in ctx.fs.listdir(full) if ctx.fs.is_dir(posixpath.join(full, n)))
            except FsError:
                links = 2
        size = human(node.size) if flags.get("h") else str(node.size)
        shown = name
        if node.type == "link":
            shown = f"{name} -> {node.target}"
        rows.append((mode_str(node), str(links), node.owner, node.group, size, ls_time(node.mtime), shown))
    if not rows:
        return []
    w = [max(len(r[i]) for r in rows) for i in range(5)]
    return [f"{r[0]} {r[1]:>{w[1]}} {r[2]:<{w[2]}} {r[3]:<{w[3]}} {r[4]:>{w[4]}} {r[5]} {r[6]}" for r in rows]


def _sort_entries(entries, flags):
    if flags.get("t"):
        entries.sort(key=lambda e: -e[1].mtime)
    elif flags.get("S"):
        entries.sort(key=lambda e: -e[1].size)
    else:
        entries.sort(key=lambda e: e[0].lstrip(".").lower() or e[0])
    if flags.get("r"):
        entries.reverse()
    return entries


def _ls_dir(ctx: Ctx, path: str, flags: dict) -> tuple[list[str], list[str]]:
    """returns (output lines, subdirs for -R)."""
    real = ctx.fs.realpath(path)
    names = ctx.fs.listdir(real, ctx.user)
    show_all = flags.get("a") or flags.get("all")
    if not (show_all or flags.get("A")):
        names = [n for n in names if not n.startswith(".")]
    entries = []
    for n in names:
        full = posixpath.join(real, n)
        node = ctx.fs.get(full, follow=False)
        if node is not None:
            entries.append((n, node, full))
    _sort_entries(entries, flags)
    if show_all:
        entries = [(".", ctx.fs.get(real), real), ("..", ctx.fs.get(posixpath.dirname(real) or "/"), posixpath.dirname(real) or "/")] + entries
    subdirs = [e[2] for e in entries if e[1].type == "dir" and e[0] not in (".", "..")]
    if flags.get("l") or flags.get("n"):
        blocks = sum(-(-e[1].size // 4096) * 4 for e in entries if e[1].type != "link")
        return [f"total {human(blocks * 1024) if flags.get('h') else blocks}"] + _ls_long(ctx, entries, flags), subdirs
    return [e[0] for e in entries], subdirs


@command("ls", "dir", "vdir", "ll", "la", "l")
def ls(ctx: Ctx, args: list[str]) -> Result:
    flags, paths = parse_flags(args)
    if ctx.name in ("ll", "vdir"):
        flags.update({"l": True, "a": ctx.name == "ll"})
    if ctx.name == "la":
        flags["A"] = True
    one_per_line = flags.get("1") or not ctx.state.tty or ctx.stdin is not None
    paths = paths or ["."]
    out, err, code = [], [], 0
    files, dirs = [], []
    for p in paths:
        try:
            node = ctx.fs.stat(ctx.path(p), ctx.user, follow=not (flags.get("l") or flags.get("d")))
        except FsError as e:
            err.append(f"ls: cannot access '{p}': {e.message}\n")
            code = 2
            continue
        if node.type == "dir" and not flags.get("d"):
            dirs.append(p)
        elif node.type == "link" and ctx.fs.is_dir(ctx.path(p)) and not flags.get("d"):
            dirs.append(p)
        else:
            files.append((p, node, ctx.path(p)))
    long = flags.get("l") or flags.get("n")
    if files:
        _sort_entries(files, flags)
        if long:
            out.extend(l + "\n" for l in _ls_long(ctx, files, flags))
        elif one_per_line:
            out.extend(f[0] + "\n" for f in files)
        else:
            out.append(columns([f[0] for f in files]))
    queue = list(dirs)
    header = len(paths) > 1 or flags.get("R")
    first = not files
    while queue:
        d = queue.pop(0)
        try:
            lines, subdirs = _ls_dir(ctx, ctx.path(d), flags)
        except FsError as e:
            err.append(f"ls: cannot open directory '{d}': {e.message}\n")
            code = 2
            continue
        if not first:
            out.append("\n")
        first = False
        if header:
            out.append(f"{d}:\n")
        if long or one_per_line:
            out.extend(l + "\n" for l in lines)
        else:
            out.append(columns(lines))
        if flags.get("R"):
            rel = [posixpath.join(d, posixpath.basename(s)) for s in subdirs]
            queue = rel + queue
    return Result("".join(out), "".join(err), code)


@command("cd")
def cd(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    target = args[0] if args else st.env.get("HOME", "/")
    if len(args) > 1:
        return Result(err="-bash: cd: too many arguments\n", code=1)
    if target == "-":
        target = st.oldpwd or st.cwd
    path = ctx.path(target)
    try:
        node = ctx.fs.stat(path, ctx.user)
    except FsError as e:
        return Result(err=f"-bash: cd: {target}: {e.message}\n", code=1)
    if node.type != "dir":
        return Result(err=f"-bash: cd: {target}: Not a directory\n", code=1)
    if not ctx.fs.allowed(node, ctx.user, 0o1):
        return Result(err=f"-bash: cd: {target}: Permission denied\n", code=1)
    st.oldpwd = st.cwd
    st.cwd = path
    st.env["OLDPWD"] = st.oldpwd
    st.env["PWD"] = path
    return Result(out=path + "\n" if args and args[0] == "-" else "")


@command("pwd")
def pwd(ctx: Ctx, args: list[str]) -> Result:
    return Result(ctx.state.cwd + "\n")


@command("cat", "less", "more", "zcat")
def cat(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args)
    items, err, code = read_inputs(ctx, files)
    if ctx.name == "zcat":
        return Result(err="".join(f"gzip: {n}: not in gzip format\n" for n, _ in items) + err, code=1)
    text = "".join(t for _, t in items)
    if flags.get("n"):
        lines = text.split("\n")
        trail = lines[-1] == ""
        if trail:
            lines.pop()
        text = "".join(f"{i:>6}\t{l}\n" for i, l in enumerate(lines, 1))
    return Result(text, err, code)


@command("touch")
def touch(ctx: Ctx, args: list[str]) -> Result:
    _, files = parse_flags(args)
    if not files:
        return Result(err="touch: missing file operand\nTry 'touch --help' for more information.\n", code=1)
    err, code = [], 0
    for f in files:
        try:
            ctx.fs.touch(ctx.path(f), ctx.user)
        except FsError as e:
            err.append(f"touch: cannot touch '{f}': {e.message}\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("mkdir")
def mkdir(ctx: Ctx, args: list[str]) -> Result:
    flags, dirs = parse_flags(args, with_value="m")
    if not dirs:
        return Result(err="mkdir: missing operand\nTry 'mkdir --help' for more information.\n", code=1)
    err, code = [], 0
    for d in dirs:
        try:
            ctx.fs.mkdir(ctx.path(d), ctx.user, parents=bool(flags.get("p")))
        except FsError as e:
            err.append(f"mkdir: cannot create directory '{d}': {e.message}\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("rmdir")
def rmdir(ctx: Ctx, args: list[str]) -> Result:
    _, dirs = parse_flags(args)
    err, code = [], 0
    for d in dirs:
        try:
            if not ctx.fs.is_dir(ctx.path(d)):
                raise FsError("ENOTDIR" if ctx.fs.exists(ctx.path(d)) else "ENOENT", d)
            ctx.fs.remove(ctx.path(d), ctx.user, dir_ok=True)
        except FsError as e:
            err.append(f"rmdir: failed to remove '{d}': {e.message}\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("rm")
def rm(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args)
    force = flags.get("f") or flags.get("force")
    recursive = flags.get("r") or flags.get("R") or flags.get("recursive")
    if not files:
        if force:
            return Result()
        return Result(err="rm: missing operand\nTry 'rm --help' for more information.\n", code=1)
    err, code = [], 0
    for f in files:
        path = ctx.path(f)
        if path == "/" and recursive and not flags.get("no-preserve-root"):
            err.append("rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n")
            code = 1
            continue
        if path == "/" and recursive:
            for name in ctx.fs.listdir("/"):
                try:
                    ctx.fs.remove("/" + name, ctx.user, recursive=True, dir_ok=True)
                except FsError:
                    pass
            continue
        try:
            ctx.fs.remove(path, ctx.user, recursive=bool(recursive), dir_ok=bool(recursive or flags.get("d")))
        except FsError as e:
            if force and e.code == "ENOENT":
                continue
            err.append(f"rm: cannot remove '{f}': {e.message}\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("cp")
def cp(ctx: Ctx, args: list[str]) -> Result:
    flags, paths = parse_flags(args)
    recursive = flags.get("r") or flags.get("R") or flags.get("a") or flags.get("recursive")
    if len(paths) < 2:
        return Result(err="cp: missing destination file operand after '" + (paths[0] if paths else "") + "'\nTry 'cp --help' for more information.\n" if paths else "cp: missing file operand\nTry 'cp --help' for more information.\n", code=1)
    *srcs, dst = paths
    if len(srcs) > 1 and not ctx.fs.is_dir(ctx.path(dst)):
        return Result(err=f"cp: target '{dst}' is not a directory\n", code=1)
    err, code = [], 0
    for s in srcs:
        try:
            if ctx.fs.is_dir(ctx.path(s)) and not recursive:
                err.append(f"cp: -r not specified; omitting directory '{s}'\n")
                code = 1
                continue
            ctx.fs.copy(ctx.path(s), ctx.path(dst), ctx.user, recursive=bool(recursive))
        except FsError as e:
            err.append(f"cp: cannot stat '{s}': {e.message}\n" if e.code == "ENOENT" else f"cp: cannot create regular file '{dst}': {e.message}\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("mv")
def mv(ctx: Ctx, args: list[str]) -> Result:
    _, paths = parse_flags(args)
    if len(paths) < 2:
        return Result(err="mv: missing file operand\nTry 'mv --help' for more information.\n", code=1)
    *srcs, dst = paths
    err, code = [], 0
    for s in srcs:
        try:
            ctx.fs.move(ctx.path(s), ctx.path(dst), ctx.user)
        except FsError as e:
            verb = "stat" if e.code == "ENOENT" else "move"
            err.append(f"mv: cannot {verb} '{s}': {e.message}\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("ln")
def ln(ctx: Ctx, args: list[str]) -> Result:
    flags, paths = parse_flags(args)
    if len(paths) < 2:
        return Result(err="ln: missing file operand\n", code=1)
    target, link = paths[0], paths[1]
    path = ctx.path(link)
    if ctx.fs.is_dir(path):
        path = posixpath.join(path, posixpath.basename(target))
    try:
        if flags.get("f") and ctx.fs.get(path, follow=False) is not None:
            ctx.fs.remove(path, ctx.user)
        if flags.get("s"):
            ctx.fs.symlink(target, path, ctx.user)
        else:
            ctx.fs.copy(ctx.path(target), path, ctx.user)
    except FsError as e:
        return Result(err=f"ln: failed to create link '{link}': {e.message}\n", code=1)
    return Result()


SYM_BITS = {"r": 4, "w": 2, "x": 1}


def apply_mode(spec: str, mode: int, is_dir: bool) -> int | None:
    if spec.isdigit() and all(c in "01234567" for c in spec):
        return int(spec, 8)
    for clause in spec.split(","):
        i = 0
        who = ""
        while i < len(clause) and clause[i] in "ugoa":
            who += clause[i]
            i += 1
        who = who or "a"
        if i >= len(clause) or clause[i] not in "+-=":
            return None
        while i < len(clause) and clause[i] in "+-=":
            op = clause[i]
            i += 1
            perms = ""
            while i < len(clause) and clause[i] in "rwxXst":
                perms += clause[i]
                i += 1
            bits = 0
            for p in perms:
                if p in SYM_BITS:
                    bits |= SYM_BITS[p]
                elif p == "X" and (is_dir or mode & 0o111):
                    bits |= 1
            mask = 0
            special = 0
            for w in ("ugo" if "a" in who else who):
                shift = {"u": 6, "g": 3, "o": 0}[w]
                mask |= bits << shift
                if "s" in perms and w in "ug":
                    special |= 0o4000 if w == "u" else 0o2000
                if "t" in perms and w == "o":
                    special |= 0o1000
            if op == "+":
                mode |= mask | special
            elif op == "-":
                mode &= ~(mask | special)
            else:
                for w in ("ugo" if "a" in who else who):
                    shift = {"u": 6, "g": 3, "o": 0}[w]
                    mode &= ~(0o7 << shift)
                mode |= mask | special
    return mode


@command("chmod")
def chmod(ctx: Ctx, args: list[str]) -> Result:
    recursive = "-R" in args or "--recursive" in args
    rest = [a for a in args if a not in ("-R", "--recursive", "-v", "-f", "-c")]
    if len(rest) < 2:
        return Result(err="chmod: missing operand\nTry 'chmod --help' for more information.\n", code=1)
    spec, files = rest[0], rest[1:]
    err, code = [], 0
    for f in files:
        try:
            targets = [p for p, _ in ctx.fs.walk(ctx.path(f), ctx.user)] if recursive else [ctx.path(f)]
            if not targets:
                raise FsError("ENOENT", f)
            for t in targets:
                node = ctx.fs.stat(t, ctx.user)
                new = apply_mode(spec, node.mode, node.type == "dir")
                if new is None:
                    return Result(err=f"chmod: invalid mode: '{spec}'\nTry 'chmod --help' for more information.\n", code=1)
                ctx.fs.chmod(t, new, ctx.user)
        except FsError as e:
            verb = "access" if e.code == "ENOENT" else "change permissions of"
            err.append(f"chmod: cannot {verb} '{f}': {e.message}\n" if e.code == "ENOENT" else f"chmod: changing permissions of '{f}': Operation not permitted\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("chown", "chgrp")
def chown(ctx: Ctx, args: list[str]) -> Result:
    recursive = "-R" in args
    rest = [a for a in args if not a.startswith("-")]
    if len(rest) < 2:
        return Result(err=f"{ctx.name}: missing operand\n", code=1)
    spec, files = rest[0], rest[1:]
    if ctx.name == "chgrp":
        owner, group = None, spec
    else:
        owner, _, group = spec.replace(".", ":").partition(":")
        group = group or None
    err, code = [], 0
    for f in files:
        try:
            targets = [p for p, _ in ctx.fs.walk(ctx.path(f), ctx.user)] if recursive else [ctx.path(f)]
            if not targets:
                raise FsError("ENOENT", f)
            for t in targets:
                node = ctx.fs.stat(t, ctx.user)
                if owner and owner != node.owner and ctx.state.passwd_entry(owner) is None:
                    return Result(err=f"chown: invalid user: '{spec}'\n", code=1)
                ctx.fs.chown(t, owner or node.owner, group, ctx.user)
        except FsError as e:
            if e.code == "ENOENT":
                err.append(f"{ctx.name}: cannot access '{f}': No such file or directory\n")
            else:
                err.append(f"{ctx.name}: changing ownership of '{f}': Operation not permitted\n")
            code = 1
    return Result(err="".join(err), code=code)


@command("find")
def find(ctx: Ctx, args: list[str]) -> Result:
    roots = []
    i = 0
    while i < len(args) and not args[i].startswith("-") and args[i] not in ("(", "!"):
        roots.append(args[i])
        i += 1
    roots = roots or ["."]
    name = iname = kind = user = None
    maxdepth = 99
    exec_cmd: list[str] | None = None
    delete = False
    negate_next = False
    negated_name = None
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a == "!" or a == "-not":
            negate_next = True
            i += 1
            continue
        if a == "-name":
            if negate_next:
                negated_name = nxt
            else:
                name = nxt
            i += 2
        elif a == "-iname":
            iname = nxt.lower()
            i += 2
        elif a == "-type":
            kind = {"f": "file", "d": "dir", "l": "link"}.get(nxt)
            i += 2
        elif a == "-maxdepth":
            maxdepth = int(nxt) if nxt.isdigit() else 99
            i += 2
        elif a == "-user":
            user = nxt
            i += 2
        elif a == "-exec":
            j = i + 1
            exec_cmd = []
            while j < len(args) and args[j] not in (";", "+"):
                exec_cmd.append(args[j])
                j += 1
            i = j + 1
        elif a == "-delete":
            delete = True
            i += 1
        elif a in ("-perm", "-size", "-mtime", "-newer", "-path", "-mmin", "-group", "-regex"):
            i += 2
        else:
            i += 1
        negate_next = False
    out, err, code = [], [], 0

    def visit(path: str, shown: str, depth: int) -> None:
        nonlocal code
        node = ctx.fs.get(path, follow=False)
        if node is None:
            return
        base = posixpath.basename(shown) or shown
        ok = True
        if name and not fnmatch.fnmatchcase(base, name):
            ok = False
        if negated_name and fnmatch.fnmatchcase(base, negated_name):
            ok = False
        if iname and not fnmatch.fnmatchcase(base.lower(), iname):
            ok = False
        if kind and node.type != kind:
            ok = False
        if user and node.owner != user:
            ok = False
        if ok:
            if exec_cmd is not None:
                line = " ".join(shlex.quote(shown) if part == "{}" else shlex.quote(part) for part in exec_cmd)
                r = ctx.run(line)
                out.append(r.out)
            elif delete:
                try:
                    ctx.fs.remove(path, ctx.user, recursive=True, dir_ok=True)
                except FsError:
                    pass
            else:
                out.append(shown + "\n")
        if node.type == "dir" and depth < maxdepth and len(out) < 5000:
            try:
                names = ctx.fs.listdir(path, ctx.user)
            except FsError as e:
                err.append(f"find: '{shown}': {e.message}\n")
                code = 1
                return
            for n in names:
                visit(posixpath.join(path, n), posixpath.join(shown, n) if shown != "/" else "/" + n, depth + 1)

    for r in roots:
        path = ctx.path(r)
        if not ctx.fs.exists(path):
            err.append(f"find: '{r}': No such file or directory\n")
            code = 1
            continue
        visit(ctx.fs.realpath(path), r.rstrip("/") or "/", 0)
    return Result("".join(out), "".join(err), code)


def describe(node: Node, content: str) -> str:
    if node.type == "dir":
        return "directory"
    if node.type == "link":
        return f"symbolic link to {node.target}"
    if not content:
        return "empty"
    if content.startswith(ELF_MAGIC):
        return ("ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, "
                "interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped")
    if content.startswith("\u001f\u008b"):
        return "gzip compressed data, from Unix"
    if content.startswith("#!/bin/bash") or content.startswith("#!/usr/bin/env bash"):
        return "Bourne-Again shell script, ASCII text executable"
    if content.startswith("#!/bin/sh"):
        return "POSIX shell script, ASCII text executable"
    if content.startswith("#!") and "python" in content.split("\n", 1)[0]:
        return "Python script, ASCII text executable"
    if content.lstrip().lower().startswith(("<!doctype html", "<html")):
        return "HTML document, ASCII text"
    return "ASCII text" if content.isascii() else "UTF-8 Unicode text"


@command("file")
def file_cmd(ctx: Ctx, args: list[str]) -> Result:
    _, files = parse_flags(args)
    if not files:
        return Result(err="Usage: file [-bcCdEhikLlNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n", code=1)
    out = []
    for f in files:
        node = ctx.fs.get(ctx.path(f), follow=False)
        if node is None:
            out.append(f"{f}: cannot open `{f}' (No such file or directory)\n")
            continue
        content = node.content if node.type == "file" else ""
        out.append(f"{f}: {describe(node, content)}\n")
    return Result("".join(out))


@command("stat")
def stat(ctx: Ctx, args: list[str]) -> Result:
    _, files = parse_flags(args)
    if not files:
        return Result(err="stat: missing operand\nTry 'stat --help' for more information.\n", code=1)
    out, err, code = [], [], 0
    for f in files:
        try:
            node = ctx.fs.stat(ctx.path(f), ctx.user, follow=False)
        except FsError as e:
            err.append(f"stat: cannot statx '{f}': {e.message}\n")
            code = 1
            continue
        uid, _ = uid_of(ctx, node.owner)
        gid = uid_of(ctx, node.group)[1] if ctx.state.passwd_entry(node.group) else 0
        kind = {"dir": "directory", "file": "regular file" if node.size else "regular empty file", "link": "symbolic link"}[node.type]
        ts = datetime.fromtimestamp(node.mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000000000 +0000")
        out.append(
            f"  File: {f}\n  Size: {node.size:<15} Blocks: {-(-node.size // 4096) * 8:<10} IO Block: 4096   {kind}\n"
            f"Device: fc01h/64513d\tInode: {abs(hash(ctx.path(f))) % 900000 + 100000:<11} Links: 1\n"
            f"Access: ({node.mode:04o}/{mode_str(node)})  Uid: ({uid:>5}/{node.owner:>8})   Gid: ({gid:>5}/{node.group:>8})\n"
            f"Access: {ts}\nModify: {ts}\nChange: {ts}\n Birth: -\n"
        )
    return Result("".join(out), "".join(err), code)


@command("readlink")
def readlink(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args)
    out = []
    for f in files:
        if flags.get("f") or flags.get("e"):
            out.append(ctx.fs.realpath(ctx.path(f)) + "\n")
            continue
        node = ctx.fs.get(ctx.path(f), follow=False)
        if node is None or node.type != "link":
            return Result("".join(out), code=1)
        out.append(node.target + "\n")
    return Result("".join(out))


@command("du")
def du(ctx: Ctx, args: list[str]) -> Result:
    flags, paths = parse_flags(args, with_value="d")
    paths = paths or ["."]
    out, err = [], []

    def fmt(kb: int) -> str:
        return human(kb * 1024) if flags.get("h") else str(kb)

    for p in paths:
        path = ctx.path(p)
        if not ctx.fs.exists(path):
            err.append(f"du: cannot access '{p}': No such file or directory\n")
            continue
        totals: dict[str, int] = {}
        for full, node in ctx.fs.walk(path, ctx.user):
            kb = 4 if node.type == "dir" else -(-node.size // 4096) * 4
            cur = full
            real_root = ctx.fs.realpath(path)
            while True:
                totals[cur] = totals.get(cur, 0) + kb
                if cur == real_root or cur == "/":
                    break
                cur = posixpath.dirname(cur) or "/"
        real_root = ctx.fs.realpath(path)
        if flags.get("s"):
            out.append(f"{fmt(totals.get(real_root, 0))}\t{p}\n")
            continue
        for d in sorted((k for k in totals if ctx.fs.is_dir(k)), key=lambda k: (-k.count("/"), k)):
            shown = p.rstrip("/") + d[len(real_root):] if d != real_root else p
            out.append(f"{fmt(totals[d])}\t{shown}\n")
    if flags.get("c"):
        out.append(f"{fmt(0)}\ttotal\n")
    return Result("".join(out), "".join(err), 1 if err else 0)


@command("tee")
def tee(ctx: Ctx, args: list[str]) -> Result:
    flags, files = parse_flags(args)
    data = ctx.stdin or ""
    err = []
    for f in files:
        try:
            ctx.fs.write(ctx.path(f), data, ctx.user, append=bool(flags.get("a")))
        except FsError as e:
            err.append(f"tee: {f}: {e.message}\n")
    return Result(data, "".join(err), 1 if err else 0)
