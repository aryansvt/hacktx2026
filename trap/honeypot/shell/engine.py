"""rules engine. every command is a python function that formats text from the
virtual fs and system.json. nothing is ever executed on the host.
"""

from __future__ import annotations

import copy
import fnmatch
import json
import posixpath
import time
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Callable

from ..vfs import BaseFS, FsError, Overlay, norm
from .parser import Command, ParseError, parse_command, split_line

DATA = Path(__file__).resolve().parent.parent / "data"
MAX_DEPTH = 3  # nested sh -c / $(..) / script runs
MAX_OUTPUT = 200_000
ELF_MAGIC = "\u007fELF"


@dataclass
class Result:
    out: str = ""
    err: str = ""
    code: int = 0


@dataclass
class ShellState:
    fs: Overlay
    system: dict
    user: str = "root"
    cwd: str = "/root"
    env: dict[str, str] = field(default_factory=dict)
    history: list[str] = field(default_factory=list)
    last_status: int = 0
    tty: bool = True
    # what w/who/env show as the client. never the attacker's real ip.
    display_ip: str = "10.0.4.1"
    display_port: int = 51022
    pid: int = 51234
    started: float = field(default_factory=time.time)
    user_stack: list[tuple[str, str]] = field(default_factory=list)
    killed: set[int] = field(default_factory=set)
    services: dict[str, str] = field(default_factory=dict)
    public_ip: str = "203.0.113.10"
    exit_requested: bool = False
    oldpwd: str = ""
    # answers installed commands the engine doesn't model (the llm fallback sets it per line)
    unknown: Callable[["ShellState", list[str], str | None], Result] | None = None

    def snapshot(self) -> tuple:
        """everything a line can change, so a line can be rolled back and run again."""
        values = {f.name: copy.copy(getattr(self, f.name)) for f in fields(self) if f.name not in _NOT_SNAPSHOT}
        return self.fs.snapshot(), values

    def restore(self, snap: tuple) -> None:
        fs_snap, values = snap
        self.fs.restore(fs_snap)
        for name, value in values.items():
            setattr(self, name, copy.copy(value))

    @property
    def hostname(self) -> str:
        return self.system["hostname"]

    @property
    def is_root(self) -> bool:
        return self.user == "root"

    def passwd_entry(self, user: str) -> list[str] | None:
        try:
            text = self.fs.read("/etc/passwd")
        except FsError:
            return None
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) >= 7 and parts[0] == user:
                return parts
        return None

    def home_of(self, user: str) -> str | None:
        entry = self.passwd_entry(user)
        return entry[5] if entry else None

    def prompt(self) -> str:
        home = self.env.get("HOME", "")
        cwd = self.cwd
        if home and home != "/" and (cwd == home or cwd.startswith(home + "/")):
            cwd = "~" + cwd[len(home):]
        return f"{self.user}@{self.hostname}:{cwd}{'#' if self.is_root else '$'} "


_NOT_SNAPSHOT = {"fs", "system", "unknown"}


class Ctx:
    """what a command function sees."""

    def __init__(self, engine: "Engine", state: ShellState, name: str, stdin: str | None, depth: int):
        self.engine = engine
        self.state = state
        self.name = name
        self.stdin = stdin
        self.depth = depth

    @property
    def fs(self) -> Overlay:
        return self.state.fs

    @property
    def user(self) -> str:
        return self.state.user

    @property
    def system(self) -> dict:
        return self.state.system

    def path(self, p: str) -> str:
        return norm(p, self.state.cwd)

    def fs_err(self, e: FsError, path: str, verb: str = "") -> str:
        target = f"cannot {verb} '{path}'" if verb else path
        return f"{self.name}: {target}: {e.message}\n"

    def run(self, line: str) -> Result:
        """re-run a line through the engine (sh -c, xargs, scripts). still pure emulation."""
        return self.engine.run(self.state, line, self.depth + 1)


CommandFn = Callable[[Ctx, list[str]], Result]
REGISTRY: dict[str, CommandFn] = {}


def command(*names: str):
    def wrap(fn: CommandFn) -> CommandFn:
        for n in names:
            REGISTRY[n] = fn
        return fn

    return wrap


def load_system() -> dict:
    return json.loads((DATA / "system.json").read_text(encoding="utf-8"))


_BASE: BaseFS | None = None


def load_base() -> BaseFS:
    global _BASE
    if _BASE is None:
        _BASE = BaseFS.load(DATA / "fs_base.json")
    return _BASE


class _Expander:
    def __init__(self, engine: "Engine", state: ShellState, depth: int):
        self.engine, self.state, self.depth = engine, state, depth

    def var(self, name: str) -> str:
        s = self.state
        special = {"?": str(s.last_status), "$": str(s.pid), "#": "0", "0": "-bash", "!": "", "@": "", "*": "", "-": "himBHs"}
        if name in special:
            return special[name]
        if name == "PWD":
            return s.cwd
        if name == "RANDOM":
            return str(int(time.time() * 1000) % 32768)
        return s.env.get(name, "")

    def substitute(self, script: str) -> str:
        if self.depth >= MAX_DEPTH:
            return ""
        res = self.engine.run(self.state, script, self.depth + 1)
        return res.out.rstrip("\n")

    def home(self, user: str) -> str | None:
        if not user:
            return self.state.env.get("HOME", "/root")
        return self.state.home_of(user)

    def glob(self, pattern: str) -> list[str]:
        absolute = pattern.startswith("/")
        parts = [p for p in pattern.split("/") if p]
        bases = ["/" if absolute else ""]
        for i, part in enumerate(parts):
            nxt = []
            for b in bases:
                real = norm(b or ".", self.state.cwd)
                if any(ch in part for ch in "*?["):
                    try:
                        names = self.state.fs.listdir(real, self.state.user)
                    except FsError:
                        continue
                    for name in names:
                        if name.startswith(".") and not part.startswith("."):
                            continue
                        if fnmatch.fnmatchcase(name, part):
                            nxt.append(posixpath.join(b, name) if b else name)
                else:
                    cand = posixpath.join(b, part) if b else part
                    if i == len(parts) - 1 or self.state.fs.exists(norm(cand, self.state.cwd)):
                        nxt.append(cand)
            bases = nxt
        return sorted(b for b in bases if self.state.fs.exists(norm(b, self.state.cwd)))


class Engine:
    def __init__(self) -> None:
        # import for the registration side effects
        from .commands import files, system, text  # noqa: F401

    def new_state(self, user: str = "root", tty: bool = True, base: BaseFS | None = None, **kw) -> ShellState:
        fs = Overlay(base or load_base())
        state = ShellState(fs=fs, system=load_system(), user=user, tty=tty, **kw)
        entry = state.passwd_entry(user)
        home = entry[5] if entry else f"/home/{user}"
        if not fs.exists(home):
            # logins like the guest user have no seeded home; make one in the overlay
            fs.mkdir(home, parents=True)
            fs.chown(home, user, user)
        state.cwd = home
        state.env = default_env(state, user, home)
        try:
            state.history = fs.read(posixpath.join(home, ".bash_history"), user).splitlines()
        except FsError:
            state.history = []
        return state

    def run(self, state: ShellState, line: str, depth: int = 0) -> Result:
        if depth > MAX_DEPTH:
            return Result(err="bash: maximum nesting level exceeded\n", code=1)
        try:
            chain = split_line(line)
        except ParseError as e:
            state.last_status = 2
            return Result(err=f"-bash: {e}\n", code=2)
        out: list[str] = []
        status = state.last_status
        for connector, pipeline in chain:
            if state.exit_requested:
                break
            if connector == "&&" and status != 0:
                continue
            if connector == "||" and status == 0:
                continue
            res = self._pipeline(state, pipeline, depth)
            out.append(res.err)
            out.append(res.out)
            status = res.code
            state.last_status = status
            if sum(len(o) for o in out) > MAX_OUTPUT:
                break
        return Result(out="".join(out)[:MAX_OUTPUT], code=status)

    def _pipeline(self, state: ShellState, raws: list[str], depth: int) -> Result:
        stdin: str | None = None
        errs: list[str] = []
        res = Result()
        ex = _Expander(self, state, depth)
        for idx, raw in enumerate(raws):
            try:
                cmd = parse_command(raw, ex)
            except ParseError as e:
                return Result(err="".join(errs) + f"-bash: {e}\n", code=2)
            piped_in = stdin if idx > 0 else None
            res = self._simple(state, cmd, piped_in, depth)
            errs.append(res.err)
            stdin = res.out
            if state.exit_requested:
                break
        return Result(out=res.out, err="".join(errs), code=res.code)

    def _simple(self, state: ShellState, cmd: Command, stdin: str | None, depth: int) -> Result:
        if not cmd.argv:
            for name, value in cmd.assigns:
                state.env[name] = value
            # a bare redirect like `> file` still truncates the file
            return self._redirect(state, cmd, Result(), stdin)[0]
        for r in cmd.redirects:
            if r.op == "<":
                try:
                    stdin = state.fs.read(norm(r.target, state.cwd), state.user)
                except FsError as e:
                    return Result(err=f"-bash: {r.target}: {e.message}\n", code=1)
        res = self.dispatch(state, cmd.argv, stdin, depth)
        res, _ = self._redirect(state, cmd, res, stdin)
        return res

    def _redirect(self, state: ShellState, cmd: Command, res: Result, stdin: str | None) -> tuple[Result, None]:
        out, err = res.out, res.err
        for r in cmd.redirects:
            if r.op == "dup":
                if r.fd == 2 and r.target == "1":
                    out, err = out + err, ""
                elif r.fd == 1 and r.target == "2":
                    out, err = "", err + out
                continue
            if r.op not in (">", ">>"):
                continue
            data = {1: out, 2: err, -1: out + err}[r.fd] if r.fd in (1, 2, -1) else ""
            if r.fd in (1, -1):
                out = ""
            if r.fd in (2, -1):
                err = ""
            target = norm(r.target, state.cwd)
            if target in ("/dev/null", "/dev/zero"):
                continue
            if target in ("/dev/stdout", "/dev/tty"):
                out += data
                continue
            if target == "/dev/stderr":
                err += data
                continue
            try:
                state.fs.write(target, data, state.user, append=r.op == ">>")
            except FsError as e:
                err += f"-bash: {r.target}: {e.message}\n"
                res.code = 1
        return Result(out=out, err=err, code=res.code), None

    def dispatch(self, state: ShellState, argv: list[str], stdin: str | None, depth: int) -> Result:
        name = argv[0]
        if "/" in name:
            return self._run_path(state, name, argv, stdin, depth)
        fn = REGISTRY.get(name)
        if fn is None:
            if find_in_path(state, name):
                # installed but not modelled: the llm fallback answers, or a quiet success
                return state.unknown(state, argv, stdin) if state.unknown else Result()
            return Result(err=f"{name}: command not found\n", code=127)
        ctx = Ctx(self, state, name, stdin, depth)
        try:
            return fn(ctx, argv[1:])
        except FsError as e:
            return Result(err=f"{name}: {e.path}: {e.message}\n", code=1)

    def _run_path(self, state: ShellState, name: str, argv: list[str], stdin: str | None, depth: int) -> Result:
        path = norm(name, state.cwd)
        try:
            node = state.fs.stat(path, state.user)
        except FsError as e:
            return Result(err=f"-bash: {name}: {e.message}\n", code=126 if e.code == "EACCES" else 127)
        if node.type == "dir":
            return Result(err=f"-bash: {name}: Is a directory\n", code=126)
        # even root needs some x bit to run a file
        if not node.mode & 0o111 or not state.fs.allowed(node, state.user, 0o1):
            return Result(err=f"-bash: {name}: Permission denied\n", code=126)
        real = state.fs.realpath(path)
        base = posixpath.basename(real)
        if posixpath.dirname(real) in ("/usr/bin", "/usr/sbin", "/usr/local/bin"):
            if base in REGISTRY:
                return self.dispatch(state, [base] + argv[1:], stdin, depth)
            if state.unknown:
                return state.unknown(state, [base] + argv[1:], stdin)
        if node.content.startswith(ELF_MAGIC) or not node.content.strip():
            return Result(err=f"-bash: {name}: cannot execute binary file: Exec format error\n", code=126)
        return run_script(self, state, node.content, depth)


def run_script(engine: Engine, state: ShellState, text: str, depth: int) -> Result:
    """feed script lines back through the engine, one at a time."""
    if text.startswith(ELF_MAGIC):
        first = text.split("\n", 1)[0][:16]
        printable = first.encode("unicode_escape").decode().replace("\\x", "\\")
        return Result(err=f"bash: line 1: $'{printable}': command not found\n", code=127)
    outs: list[str] = []
    res = Result()
    for line in text.splitlines()[:200]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        res = engine.run(state, line, depth + 1)
        outs.append(res.out)
        if state.exit_requested:
            break
    return Result(out="".join(outs), code=res.code)


def find_in_path(state: ShellState, name: str) -> str | None:
    for d in state.env.get("PATH", "").split(":"):
        if not d:
            continue
        p = posixpath.join(d, name)
        node = state.fs.get(p)
        if node is not None and node.type == "file":
            return p
    return None


def default_env(state: ShellState, user: str, home: str) -> dict[str, str]:
    entry = state.passwd_entry(user)
    shell = entry[6] if entry else "/bin/bash"
    path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
    if user != "root":
        path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
    env = {
        "SHELL": shell,
        "PWD": home,
        "LOGNAME": user,
        "MOTD_SHOWN": "pam",
        "HOME": home,
        "LANG": "C.UTF-8",
        "SSH_CONNECTION": f"{state.display_ip} {state.display_port} {state.system['ip']} 22",
        "USER": user,
        "SHLVL": "1",
        "SSH_CLIENT": f"{state.display_ip} {state.display_port} 22",
        "XDG_RUNTIME_DIR": f"/run/user/{entry[2] if entry else 1100}",
        "PATH": path,
        "MAIL": f"/var/mail/{user}",
        "_": "/usr/bin/env",
    }
    if state.tty:
        env["TERM"] = "xterm-256color"
        env["SSH_TTY"] = "/dev/pts/0"
    return env
