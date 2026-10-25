"""system info commands, all formatted from system.json and session state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ...vfs import FsError
from ..engine import Ctx, Result, command, find_in_path
from ._util import (
    boot_time, ctime, groups_of, human, load_avg, now, parse_flags, short_time, stopped_pids, uid_of, uptime_seconds,
)

def _clock(dt: datetime) -> str:
    return f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"


def _up_text(ctx: Ctx) -> str:
    secs = int(uptime_seconds(ctx))
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    hm = f"{hours:>2}:{mins:02d}" if hours else f"{mins} min"
    if days:
        return f"{days} day{'s' if days != 1 else ''}, {hm}"
    return hm.strip()


def _load_text() -> str:
    a, b, c = load_avg()
    return f"{a:.2f}, {b:.2f}, {c:.2f}"


def _login_time(ctx: Ctx) -> datetime:
    return datetime.fromtimestamp(ctx.state.started, timezone.utc)


def _session_procs(ctx: Ctx, final: str) -> list[list]:
    st = ctx.state
    tty = "pts/0" if st.tty else "?"
    start = f"{_login_time(ctx).hour:02d}:{_login_time(ctx).minute:02d}"
    return [
        ["root", st.pid - 9, 0.0, 0.2, 17180, 10840, "?", "Ss", start, "0:00", f"sshd: {st.user}@{tty}" if st.tty else f"sshd: {st.user}"],
        [st.user, st.pid, 0.0, 0.1, 8964, 5432, tty, "Ss", start, "0:00", "-bash"],
        [st.user, st.pid + 3, 0.0, 0.0, 10072, 3516, tty, "R+", start, "0:00", final],
    ]


def _all_procs(ctx: Ctx, final: str) -> list[list]:
    gone = stopped_pids(ctx)
    procs = [p for p in ctx.system["processes"] if p[1] not in gone]
    return procs + _session_procs(ctx, final)


@command("whoami")
def whoami(ctx: Ctx, args: list[str]) -> Result:
    return Result(ctx.user + "\n")


@command("id")
def id_cmd(ctx: Ctx, args: list[str]) -> Result:
    flags, users = parse_flags(args)
    user = users[0] if users else ctx.user
    if users and ctx.state.passwd_entry(user) is None:
        return Result(err=f"id: '{user}': no such user\n", code=1)
    uid, gid = uid_of(ctx, user)
    groups = groups_of(ctx, user)
    if flags.get("u"):
        return Result((user if flags.get("n") else str(uid)) + "\n")
    if flags.get("g"):
        return Result((groups[0][0] if flags.get("n") else str(gid)) + "\n")
    if flags.get("G"):
        return Result(" ".join(g[0] if flags.get("n") else str(g[1]) for g in groups) + "\n")
    joined = ",".join(f"{g[1]}({g[0]})" for g in groups)
    return Result(f"uid={uid}({user}) gid={gid}({groups[0][0]}) groups={joined}\n")


@command("uname")
def uname(ctx: Ctx, args: list[str]) -> Result:
    flags, _ = parse_flags(args)
    s = ctx.system
    fields = {
        "s": "Linux", "n": s["hostname"], "r": s["kernel"], "v": s["kernel_build"],
        "m": "x86_64", "p": "x86_64", "i": "x86_64", "o": "GNU/Linux",
    }
    if flags.get("a") or flags.get("all"):
        order = "snrvmpio"
    else:
        order = "".join(k for k in "snrvmpio" if flags.get(k)) or "s"
    return Result(" ".join(fields[k] for k in order) + "\n")


@command("hostname")
def hostname(ctx: Ctx, args: list[str]) -> Result:
    flags, _ = parse_flags(args)
    s = ctx.system
    if flags.get("I"):
        return Result(f"{s['ip']} {s['docker_ip']} \n")
    if flags.get("i"):
        return Result("127.0.1.1\n")
    if flags.get("f"):
        return Result(f"{s['hostname']}.quillfern.lan\n")
    return Result(s["hostname"] + "\n")


@command("uptime")
def uptime(ctx: Ctx, args: list[str]) -> Result:
    flags, _ = parse_flags(args)
    if flags.get("p"):
        secs = int(uptime_seconds(ctx))
        days, rem = divmod(secs, 86400)
        weeks, days = divmod(days, 7)
        hours, rem = divmod(rem, 3600)
        parts = [f"{weeks} week{'s' if weeks != 1 else ''}"] if weeks else []
        parts += [f"{days} day{'s' if days != 1 else ''}"] if days else []
        parts += [f"{hours} hour{'s' if hours != 1 else ''}", f"{rem // 60} minutes"]
        return Result("up " + ", ".join(parts) + "\n")
    if flags.get("s"):
        return Result(boot_time(ctx).strftime("%Y-%m-%d %H:%M:%S") + "\n")
    return Result(f" {_clock(now())} up {_up_text(ctx)},  1 user,  load average: {_load_text()}\n")


@command("w")
def w(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    login = _login_time(ctx)
    tty = "pts/0" if st.tty else "-"
    return Result(
        f" {_clock(now())} up {_up_text(ctx)},  1 user,  load average: {_load_text()}\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        f"{st.user:<8} {tty:<8} {st.display_ip:<16} {login.hour:02d}:{login.minute:02d}    0.00s  0.02s  0.00s w\n"
    )


@command("who", "users")
def who(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    if ctx.name == "users":
        return Result(st.user + "\n")
    login = _login_time(ctx).strftime("%Y-%m-%d %H:%M")
    return Result(f"{st.user:<8} {'pts/0':<12} {login} ({st.display_ip})\n")


@command("ps")
def ps(ctx: Ctx, args: list[str]) -> Result:
    joined = "".join(a.lstrip("-") for a in args)
    full = any(c in joined for c in "aexA")
    if not full:
        st = ctx.state
        tty = "pts/0" if st.tty else "?"
        return Result(
            "    PID TTY          TIME CMD\n"
            f"{st.pid:>7} {tty:<8} 00:00:00 bash\n"
            f"{st.pid + 3:>7} {tty:<8} 00:00:00 ps\n"
        )
    final = "ps " + " ".join(args)
    procs = _all_procs(ctx, final.strip())
    if "f" in joined and "e" in joined or args[:1] == ["-ef"]:
        out = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
        for p in procs:
            ppid = 0 if p[1] in (1, 2) else 2 if p[10].startswith("[") else 1
            t = p[9] if ":" in p[9] else "0:00"
            mins, secs = t.split(":")
            out.append(f"{p[0]:<8} {p[1]:>7} {ppid:>7}  0 {p[8]:<5} {p[6]:<8} 00:{int(mins):02d}:{int(secs):02d} {p[10]}")
        return Result("\n".join(out) + "\n")
    out = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
    for p in procs:
        out.append(f"{p[0]:<10} {p[1]:>6} {p[2]:>4} {p[3]:>4} {p[4]:>6} {p[5]:>5} {p[6]:<8} {p[7]:<4} {p[8]:>5} {p[9]:>6} {p[10]}")
    return Result("\n".join(out) + "\n")


@command("top", "htop")
def top(ctx: Ctx, args: list[str]) -> Result:
    m = ctx.system["mem_mb"]
    procs = _all_procs(ctx, "top")
    rows = sorted(procs, key=lambda p: (-p[2], -p[3]))[:15]
    lines = [
        f"top - {_clock(now())} up {_up_text(ctx)},  1 user,  load average: {_load_text()}",
        f"Tasks: {len(procs) + 80:>3} total,   1 running, {len(procs) + 79:>3} sleeping,   0 stopped,   0 zombie",
        "%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st",
        f"MiB Mem :   {m['total']:.1f} total,    {m['free']:.1f} free,   {m['used']:.1f} used,   {m['buff_cache']:.1f} buff/cache",
        f"MiB Swap:      0.0 total,      0.0 free,      0.0 used.   {m['available']:.1f} avail Mem",
        "",
        "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
    ]
    for p in rows:
        name = p[10].split()[0].strip("[]").split("/")[-1].rstrip(":")
        lines.append(f"{p[1]:>7} {p[0][:8]:<8}  20   0 {p[4]:>7} {p[5]:>6} {p[5] // 3:>6} {p[7][0]} {p[2]:>5.1f} {p[3]:>5.1f}   {p[9]:>7} {name}")
    return Result("\n".join(lines) + "\n")


@command("free")
def free(ctx: Ctx, args: list[str]) -> Result:
    flags, _ = parse_flags(args)
    m = ctx.system["mem_mb"]
    keys = ["total", "used", "free", "shared", "buff_cache", "available"]
    if flags.get("h"):
        def fmt(mb):
            return f"{mb / 1024:.1f}Gi" if mb >= 1024 else f"{mb}Mi"
        vals = [fmt(m[k]) for k in keys]
        swap = ["0B", "0B", "0B"]
    elif flags.get("m"):
        vals = [str(m[k]) for k in keys]
        swap = ["0", "0", "0"]
    elif flags.get("g"):
        vals = [str(m[k] // 1024) for k in keys]
        swap = ["0", "0", "0"]
    else:
        vals = [str(m[k] * 1024) for k in keys]
        swap = ["0", "0", "0"]
    head = "               total        used        free      shared  buff/cache   available"
    mem = "Mem:   " + "".join(f"{v:>12}" for v in vals)
    sw = "Swap:  " + "".join(f"{v:>12}" for v in swap)
    return Result(f"{head}\nMem:{mem[4:]}\n{sw}\n")


@command("df")
def df(ctx: Ctx, args: list[str]) -> Result:
    flags, _ = parse_flags(args)
    show_type = flags.get("T")
    rows = []
    for dev, fstype, size, used, avail, mount in ctx.system["disks"]:
        pct = f"{round(used * 100 / size) if size else 0}%"
        if flags.get("h"):
            nums = [human(x * 1024 * 1024) for x in (size, used, avail)]
        else:
            nums = [str(x * 1024) for x in (size, used, avail)]
        rows.append([dev] + ([fstype] if show_type else []) + nums + [pct, mount])
    head = ["Filesystem"] + (["Type"] if show_type else []) + (["Size", "Used", "Avail"] if flags.get("h") else ["1K-blocks", "Used", "Available"]) + ["Use%", "Mounted on"]
    table = [head] + rows
    # gnu df pads the device column to 14 and numbers to 5
    widths = [max(max(len(r[i]) for r in table), 14 if i == 0 else 5) for i in range(len(head) - 1)]
    lines = []
    for r in table:
        cells = []
        for i, cell in enumerate(r[:-1]):
            cells.append(cell.ljust(widths[i]) if i < (2 if show_type else 1) else cell.rjust(widths[i]))
        lines.append(" ".join(cells) + " " + r[-1])
    return Result("\n".join(lines) + "\n")


@command("nproc")
def nproc(ctx: Ctx, args: list[str]) -> Result:
    return Result(f"{ctx.system['cpus']}\n")


@command("lscpu")
def lscpu(ctx: Ctx, args: list[str]) -> Result:
    s = ctx.system
    n = s["cpus"]
    rows = [
        ("Architecture", "x86_64"), ("CPU op-mode(s)", "32-bit, 64-bit"), ("Address sizes", "40 bits physical, 48 bits virtual"),
        ("Byte Order", "Little Endian"), ("CPU(s)", str(n)), ("On-line CPU(s) list", f"0-{n - 1}"),
        ("Vendor ID", "GenuineIntel"), ("Model name", s["cpu_model"]), ("CPU family", "6"), ("Model", "85"),
        ("Thread(s) per core", "1"), ("Core(s) per socket", "1"), ("Socket(s)", str(n)), ("Stepping", "4"),
        ("BogoMIPS", "4589.21"), ("Hypervisor vendor", "KVM"), ("Virtualization type", "full"),
        ("L1d cache", f"{32 * n} KiB ({n} instances)"), ("L1i cache", f"{32 * n} KiB ({n} instances)"),
        ("L2 cache", f"{4 * n} MiB ({n} instances)"), ("L3 cache", f"{16 * n} MiB ({n} instances)"),
        ("NUMA node(s)", "1"), ("NUMA node0 CPU(s)", f"0-{n - 1}"),
    ]
    return Result("".join(f"{(k + ':'):<26}{v}\n" for k, v in rows))


@command("date")
def date(ctx: Ctx, args: list[str]) -> Result:
    t = now()
    fmt = next((a for a in args if a.startswith("+")), None)
    if fmt:
        safe = fmt[1:].replace("%s", str(int(t.timestamp()))).replace("%N", "000000000")
        try:
            return Result(t.strftime(safe) + "\n")
        except ValueError:
            return Result(safe + "\n")
    return Result(ctime(t) + "\n")


@command("env", "printenv")
def env(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    values = dict(st.env)
    values["PWD"] = st.cwd
    if ctx.name == "printenv" and args:
        found = [values[a] for a in args if a in values]
        return Result("".join(v + "\n" for v in found), code=0 if len(found) == len(args) else 1)
    if ctx.name == "env" and args:
        return Result(err=f"env: '{args[0]}': No such file or directory\n", code=127)
    return Result("".join(f"{k}={v}\n" for k, v in values.items()))


@command("export")
def export(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    names = [a for a in args if a != "-p"]
    if not names:
        return Result("".join(f'declare -x {k}="{v}"\n' for k, v in sorted(st.env.items())))
    for a in names:
        key, eq, value = a.partition("=")
        if eq:
            st.env[key] = value
        else:
            st.env.setdefault(key, "")
    return Result()


@command("unset")
def unset(ctx: Ctx, args: list[str]) -> Result:
    for a in args:
        if not a.startswith("-"):
            ctx.state.env.pop(a, None)
    return Result()


@command("history")
def history(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    if args[:1] == ["-c"]:
        st.history.clear()
        return Result()
    items = st.history
    if args and args[0].isdigit():
        items = items[-int(args[0]):]
    start = len(st.history) - len(items) + 1
    return Result("".join(f"{i:>5}  {line}\n" for i, line in enumerate(items, start)))


@command("which")
def which(ctx: Ctx, args: list[str]) -> Result:
    _, names = parse_flags(args)
    out, code = [], 0
    for n in names:
        p = find_in_path(ctx.state, n)
        if p:
            out.append(p + "\n")
        else:
            code = 1
    return Result("".join(out), code=code)


@command("exit", "logout")
def exit_cmd(ctx: Ctx, args: list[str]) -> Result:
    st = ctx.state
    code = int(args[0]) if args and args[0].isdigit() else 0
    if st.user_stack:
        # leave the shell sudo opened, back to whoever ran it
        st.user, st.cwd, st.env, login = st.user_stack.pop()
        return Result(out=("logout\n" if login else "exit\n") if st.tty else "", code=code)
    st.exit_requested = True
    return Result(out="logout\n" if st.tty else "", code=code)


@command("true", ":")
def true_cmd(ctx: Ctx, args: list[str]) -> Result:
    return Result()


@command("false")
def false_cmd(ctx: Ctx, args: list[str]) -> Result:
    return Result(code=1)


@command("clear", "reset")
def clear(ctx: Ctx, args: list[str]) -> Result:
    return Result("\x1b[H\x1b[2J\x1b[3J" if ctx.state.tty else "")


# services

def _ago(delta: timedelta) -> str:
    secs = int(delta.total_seconds())
    days, rem = divmod(secs, 86400)
    weeks, days = divmod(days, 7)
    if weeks:
        return f"{weeks} week{'s' if weeks != 1 else ''} {days} day{'s' if days != 1 else ''} ago"
    if days:
        return f"{days} day{'s' if days != 1 else ''} {rem // 3600}h ago"
    hours, rem = divmod(rem, 3600)
    return f"{hours}h {rem // 60}min ago" if hours else f"{rem // 60}min {rem % 60}s ago"


def _unit_name(arg: str) -> str:
    return arg[: -len(".service")] if arg.endswith(".service") else arg


def _service(ctx: Ctx, name: str) -> dict | None:
    return ctx.system["services"].get(name)


def _active(ctx: Ctx, name: str) -> str:
    svc = _service(ctx, name)
    return ctx.state.services.get(name, svc["active"] if svc else "inactive (dead)")


def _status(ctx: Ctx, name: str) -> Result:
    svc = _service(ctx, name)
    if svc is None:
        return Result(err=f"Unit {name}.service could not be found.\n", code=4)
    active = _active(ctx, name)
    since = boot_time(ctx) + timedelta(seconds=7)
    if name in ctx.state.services:
        since = now()
    lines = [
        f"● {name}.service - {svc['desc']}",
        f"     Loaded: loaded ({svc['unit']}; enabled; vendor preset: enabled)",
        f"     Active: {active} since {since.strftime('%a %Y-%m-%d %H:%M:%S')} UTC; {_ago(now() - since)}",
    ]
    if active.startswith("active (running)") and svc["pid"]:
        lines += [
            f"   Main PID: {svc['pid']} ({svc['main']})",
            f"      Tasks: {svc['tasks']} (limit: 4557)",
            f"     Memory: {svc['memory']}",
            f"     CGroup: /system.slice/{name}.service",
            f"             └─{svc['pid']} \"{svc['cmd']}\"",
        ]
    return Result("\n".join(lines) + "\n", code=0 if active.startswith("active") else 3)


def _control(ctx: Ctx, verb: str, name: str) -> Result:
    if _service(ctx, name) is None:
        return Result(err=f"Failed to {verb} {name}.service: Unit {name}.service not found.\n", code=5)
    if not ctx.state.is_root:
        return Result(err=f"Failed to {verb} {name}.service: Interactive authentication required.\nSee system logs and 'systemctl status {name}.service' for details.\n", code=1)
    if verb == "stop":
        ctx.state.services[name] = "inactive (dead)"
    elif verb in ("start", "restart"):
        ctx.state.services[name] = _service(ctx, name)["active"]
    return Result()


@command("systemctl")
def systemctl(ctx: Ctx, args: list[str]) -> Result:
    _, pos = parse_flags(args, long_value=("type", "state"))
    if not pos or pos[0] in ("list-units", "list-unit-files"):
        rows = []
        for name, svc in sorted(ctx.system["services"].items()):
            if svc is None:
                continue
            active = _active(ctx, name)
            state, sub = active.split(" ", 1) if " " in active else (active, "")
            rows.append(f"  {name + '.service':<30} loaded {state:<8} {sub.strip('()'):<8} {svc['desc']}")
        head = "  UNIT                           LOAD   ACTIVE   SUB      DESCRIPTION"
        return Result(head + "\n" + "\n".join(rows) + f"\n\n{len(rows)} loaded units listed.\n")
    verb, units = pos[0], [_unit_name(u) for u in pos[1:]]
    if verb == "status":
        if not units:
            return Result(f"● {ctx.system['hostname']}\n    State: running\n     Jobs: 0 queued\n   Failed: 0 units\n")
        results = [_status(ctx, u) for u in units]
        return Result("\n".join(r.out for r in results if r.out), "".join(r.err for r in results), max(r.code for r in results))
    if verb == "is-active":
        states = [_active(ctx, u).split(" ")[0] if _service(ctx, u) else "inactive" for u in units]
        return Result("".join(s + "\n" for s in states), code=0 if all(s == "active" for s in states) else 3)
    if verb == "is-enabled":
        return Result("".join(("enabled" if _service(ctx, u) else "not-found") + "\n" for u in units))
    if verb in ("start", "stop", "restart", "reload", "enable", "disable"):
        for u in units:
            r = _control(ctx, verb, u)
            if r.code:
                return r
        return Result()
    if verb == "daemon-reload":
        return Result()
    return Result(err=f"Unknown command verb {verb}.\n", code=1)


@command("service")
def service(ctx: Ctx, args: list[str]) -> Result:
    if args[:1] == ["--status-all"]:
        rows = []
        for name, svc in sorted(ctx.system["services"].items()):
            if svc is not None:
                mark = "+" if _active(ctx, name).startswith("active") else "-"
                rows.append(f" [ {mark} ]  {name}")
        return Result("\n".join(rows) + "\n")
    if len(args) < 2:
        return Result(err="Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n", code=1)
    name, verb = _unit_name(args[0]), args[1]
    if verb == "status":
        return _status(ctx, name)
    if _service(ctx, name) is None:
        return Result(err=f"{name}: unrecognized service\n", code=1)
    return _control(ctx, verb, name)


# logins and mounts

@command("last")
def last(ctx: Ctx, args: list[str]) -> Result:
    flags, pos = parse_flags(args, with_value="n")
    st = ctx.state
    rows = []
    if st.tty:
        # exec channels never write wtmp, interactive logins do
        rows.append([st.user, "pts/0", st.display_ip, short_time(_login_time(ctx)), "still logged in", ""])
    rows += ctx.system["last"]
    if pos:
        rows = [r for r in rows if r[0] in pos or (r[0] == "reboot" and "reboot" in pos)]
    limit = flags.get("n")
    if isinstance(limit, str) and limit.isdigit():
        rows = rows[: int(limit)]
    lines = []
    for user, tty, host, start, end, dur in rows:
        if end in ("still logged in", "still running"):
            lines.append(f"{user:<8} {tty:<12} {host:<16} {start}   {end}")
        else:
            lines.append(f"{user:<8} {tty:<12} {host:<16} {start} - {end}  {dur}")
    return Result("".join(l + "\n" for l in lines) + f"\nwtmp begins {ctx.system['wtmp_begins']}\n")


@command("mount")
def mount(ctx: Ctx, args: list[str]) -> Result:
    flags, pos = parse_flags(args, with_value="tTo")
    if not pos:
        kinds = flags.get("t")
        wanted = set(kinds.split(",")) if isinstance(kinds, str) else None
        rows = [m for m in ctx.system["mounts"] if wanted is None or m[2] in wanted]
        return Result("".join(f"{dev} on {mp} type {kind} ({opts})\n" for dev, mp, kind, opts in rows))
    target = pos[-1]
    if not ctx.state.is_root:
        return Result(err=f"mount: {target}: must be superuser to use mount.\n", code=32)
    if len(pos) == 1:
        return Result(err=f"mount: {target}: can't find in /etc/fstab.\n", code=1)
    source = pos[0]
    if not ctx.fs.exists(ctx.path(source)):
        return Result(err=f"mount: {target}: special device {source} does not exist.\n", code=32)
    return Result(err=f"mount: {target}: wrong fs type, bad option, bad superblock on {source}, missing codepage or helper program, or other error.\n", code=32)


# docker

def _table(rows: list[list[str]]) -> str:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "".join("   ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() + "\n" for r in rows)


def _docker_allowed(ctx: Ctx) -> bool:
    return ctx.state.is_root or any(g[0] == "docker" for g in groups_of(ctx, ctx.user))


@command("docker")
def docker(ctx: Ctx, args: list[str]) -> Result:
    if args[:1] in (["--version"], ["-v"]):
        return Result("Docker version 24.0.7, build 24.0.7-0ubuntu2~22.04.1\n")
    if not args:
        return Result("\nUsage:  docker [OPTIONS] COMMAND\n\nA self-sufficient runtime for containers\n")
    if not _docker_allowed(ctx):
        return Result(err="permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get \"http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json\": dial unix /var/run/docker.sock: connect: permission denied\n", code=1)
    sub = args[0]
    if sub == "ps" or args[:2] == ["container", "ls"]:
        if "-q" in args:
            return Result("".join(c["id"] + "\n" for c in ctx.system["containers"]))
        rows = [["CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"]]
        rows += [[c["id"], c["image"], c["command"], c["created"], c["status"], c["ports"], c["name"]] for c in ctx.system["containers"]]
        return Result(_table(rows))
    if sub == "images" or args[:2] == ["image", "ls"]:
        rows = [["REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"]] + [list(i) for i in ctx.system["images"]]
        return Result(_table(rows))
    if sub == "version":
        return Result("Client:\n Version:           24.0.7\n API version:       1.43\n Go version:        go1.21.1\n OS/Arch:           linux/amd64\n\nServer:\n Engine:\n  Version:          24.0.7\n  API version:      1.43 (minimum version 1.12)\n")
    if sub in ("pull", "run"):
        image = next((a for a in args[1:] if not a.startswith("-")), "")
        msg = f"Unable to find image '{image}' locally\n" if sub == "run" else ""
        return Result(err=msg + "docker: Error response from daemon: Get \"https://registry-1.docker.io/v2/\": dial tcp: lookup registry-1.docker.io on 127.0.0.53:53: server misbehaving.\n", code=125)
    names = {c["name"] for c in ctx.system["containers"]} | {c["id"] for c in ctx.system["containers"]}
    if sub in ("exec", "logs", "inspect", "stop", "restart", "rm"):
        target = next((a for a in args[1:] if not a.startswith("-")), "")
        if target not in names:
            return Result(err=f"Error response from daemon: No such container: {target}\n", code=1)
        return Result(target + "\n" if sub in ("stop", "restart", "rm") else "")
    return Result(err=f"docker: '{sub}' is not a docker command.\nSee 'docker --help'\n", code=1)


# cron

@command("crontab")
def crontab(ctx: Ctx, args: list[str]) -> Result:
    flags, pos = parse_flags(args, with_value="u")
    user = flags.get("u") if isinstance(flags.get("u"), str) and ctx.state.is_root else ctx.user
    path = f"/var/spool/cron/crontabs/{user}"
    if flags.get("l"):
        try:
            return Result(ctx.fs.read(path))
        except FsError:
            return Result(err=f"no crontab for {user}\n", code=1)
    if flags.get("r"):
        try:
            ctx.fs.remove(path)
        except FsError:
            return Result(err=f"no crontab for {user}\n", code=1)
        return Result()
    if pos:
        src = pos[0]
        if src == "-":
            text = ctx.stdin or ""
        else:
            try:
                text = ctx.fs.read(ctx.path(src), ctx.user)
            except FsError as e:
                return Result(err=f"{src}: {e.message}\n", code=1)
        # crontab is setgid crontab, so it writes the spool as root
        ctx.fs.write(path, text, "root")
        return Result()
    return Result(err="usage:\tcrontab [-u user] file\n\tcrontab [ -u user ] [ -i ] { -e | -l | -r }\n", code=1)
