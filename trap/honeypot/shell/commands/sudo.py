"""sudo, as close to the real one as a fake shell gets.

the password is the login user's own ssh password, and only the guest and team
logins have one sudo accepts; the ssh layer's check says yes or no and never
keeps it. a right password is cached for 15 minutes like real sudo. the
command then runs as root through the engine, so nothing touches the host.

the ssh layer asks for the password before an interactive line runs (with echo
off), since the engine can't stop mid-line to read input. exec channels have no
terminal, so they get sudo's "a terminal is required" unless they use -S.
"""

from __future__ import annotations

import posixpath
import shlex
import time

from ..engine import REGISTRY, Ctx, Result, ShellState, command, find_in_path
from ..parser import ParseError, split_line

TTL = 15 * 60
SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
VALUE_OPTS = set("ugpCDrtTRU")
LONG = {"user": "u", "stdin": "S", "non-interactive": "n", "login": "i", "shell": "s", "list": "l",
        "validate": "v", "reset-timestamp": "k", "remove-timestamp": "K", "version": "V", "help": "h",
        "preserve-env": "E", "set-home": "H", "background": "b"}
SHELLS = ("su", "bash", "sh")
SHELL_ONLY = {":", "cd", "exit", "logout", "export", "unset", "history", "l", "la", "ll"}
USAGE = (
    "usage: sudo -h | -K | -k | -V\n"
    "usage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\n"
    "usage: sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\n"
    "usage: sudo [-ABbEHkNnPS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt]\n"
    "            [-R directory] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]\n"
)
NO_TTY = ("sudo: a terminal is required to read the password; either use the -S option to read from standard input "
          "or configure an askpass helper\nsudo: a password is required\n")


def parse(args: list[str]) -> tuple[dict, list[str]]:
    """sudo's own options, then the command. sudo stops at the first word that isn't an option."""
    opts: dict = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        if a.startswith("--"):
            key, _, value = a[2:].partition("=")
            short = LONG.get(key)
            if short:
                opts[short] = value or True
        else:
            for j, ch in enumerate(a[1:], 1):
                if ch in VALUE_OPTS:
                    rest = a[j + 1:]
                    if not rest and i + 1 < len(args):
                        i += 1
                        rest = args[i]
                    opts[ch] = rest
                    break
                opts[ch] = True
        i += 1
    cmd = args[i:]
    # VAR=value before the command sets the environment; we just skip it
    while cmd and "=" in cmd[0] and not cmd[0].startswith("="):
        cmd = cmd[1:]
    return opts, cmd


def _acts(opts: dict, cmd: list[str]) -> bool:
    """does this run something that needs the password?"""
    if opts.get("V") or opts.get("h"):
        return False
    return bool(cmd or opts.get("i") or opts.get("s") or opts.get("l") or opts.get("v"))


def needs_password(state: ShellState, line: str) -> bool:
    """would this line make sudo ask for a password on the terminal? the ssh layer asks first."""
    if state.is_root or time.time() < state.sudo_until:
        return False
    try:
        chain = split_line(line)
    except ParseError:
        return False
    for _, pipeline in chain:
        for raw in pipeline:
            try:
                words = shlex.split(raw)
            except ValueError:
                words = raw.split()
            if not words or posixpath.basename(words[0]) != "sudo":
                continue
            opts, cmd = parse(words[1:])
            if _acts(opts, cmd) and not opts.get("S") and not opts.get("n"):
                return True
    return False


def _authorized(ctx: Ctx, opts: dict, stdin: str | None) -> tuple[Result | None, str | None]:
    """(an error to return, or None when allowed; stdin left for the command)."""
    st = ctx.state
    if st.is_root or time.time() < st.sudo_until:
        return None, stdin
    if st.sudo_denied:
        return Result(err=st.sudo_denied, code=1), stdin
    prompt = f"[sudo] password for {st.user}: "
    if opts.get("S"):
        first, _, rest = (stdin or "").partition("\n")
        if first and st.sudo_check and st.sudo_check(first):
            st.sudo_until = time.time() + TTL
            return Result(err=prompt), rest
        tries = f"{prompt}Sorry, try again.\n" if first else ""
        return Result(err=f"{tries}{prompt}\nsudo: no password was provided\n"
                          f"sudo: {1 if first else 0} incorrect password attempt{'' if first else 's'}\n", code=1), stdin
    if opts.get("n"):
        return Result(err="sudo: a password is required\n", code=1), stdin
    if not st.tty:
        return Result(err=NO_TTY, code=1), stdin
    # interactive, but the ssh layer never asked (a sudo hidden inside sh -c, say)
    return Result(err="sudo: a password is required\n", code=1), stdin


def _shell_env(ctx: Ctx, target: str, home: str) -> dict:
    env = dict(ctx.state.env)
    env.update({"USER": target, "LOGNAME": target, "HOME": home, "SHELL": "/bin/bash", "PATH": SECURE_PATH,
                "SUDO_USER": ctx.state.user, "MAIL": f"/var/mail/{target}"})
    return env


def _open_shell(ctx: Ctx, target: str, login: bool, pre: Result | None) -> Result:
    st = ctx.state
    home = st.home_of(target) or "/root"
    st.user_stack.append((st.user, st.cwd, dict(st.env), login))
    st.env = _shell_env(ctx, target, home)
    st.user = target
    if login:
        st.cwd = home
        st.env["PWD"] = home
    return Result(err=pre.err if pre else "")


def _run_as(ctx: Ctx, target: str, cmd: list[str], stdin: str | None, pre: Result | None) -> Result:
    st = ctx.state
    name = cmd[0]
    # sudo runs programs, not shell builtins or aliases
    known = name in REGISTRY and name not in SHELL_ONLY
    if "/" not in name and not known and not find_in_path(st, name):
        return Result(err=(pre.err if pre else "") + f"sudo: {name}: command not found\n", code=1)
    saved_user, saved_env = st.user, st.env
    st.user = target
    st.env = _shell_env(ctx, target, st.home_of(target) or "/root")
    try:
        res = ctx.engine.dispatch(st, cmd, stdin, ctx.depth + 1)
    finally:
        # the command can't keep root once it's done
        st.user, st.env = saved_user, saved_env
    return Result(res.out, (pre.err if pre else "") + res.err, res.code)


@command("sudo")
def sudo(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    opts, cmd = parse(args)
    if opts.get("V"):
        return Result("Sudo version 1.9.9\nSudoers policy plugin version 1.9.9\nSudoers file grammar version 48\n")
    if opts.get("h"):
        return Result(USAGE)
    if opts.get("K") or (opts.get("k") and not _acts(opts, cmd)):
        st.sudo_until = 0.0
        return Result()
    if not _acts(opts, cmd):
        return Result(err=USAGE, code=1)
    target = opts.get("u") if isinstance(opts.get("u"), str) else "root"
    if target != "root" and st.passwd_entry(target) is None:
        return Result(err=f"sudo: unknown user {target}\nsudo: error initializing audit plugin sudoers_audit\n", code=1)
    denied, stdin = _authorized(ctx, opts, ctx.stdin)
    if denied is not None and denied.code:
        return denied
    pre = denied
    if opts.get("v"):
        return Result(err=pre.err if pre else "")
    if opts.get("l") and not cmd:
        return Result(f"Matching Defaults entries for {st.user} on {st.hostname}:\n"
                      f"    env_reset, mail_badpass, secure_path={SECURE_PATH}, use_pty\n\n"
                      f"User {st.user} may run the following commands on {st.hostname}:\n    (ALL : ALL) ALL\n",
                      pre.err if pre else "")
    if not cmd:
        return _open_shell(ctx, target, bool(opts.get("i")), pre)
    if cmd[0] in SHELLS and all(a in ("-", "-l", "--login", "-i", "root") for a in cmd[1:]):
        login = bool(opts.get("i")) or any(a in ("-", "-l", "--login", "-i") for a in cmd[1:])
        return _open_shell(ctx, "root" if cmd[0] == "su" else target, login, pre)
    return _run_as(ctx, target, cmd, stdin, pre)
