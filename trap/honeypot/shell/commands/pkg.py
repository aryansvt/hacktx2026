"""apt, apt-get and dpkg. read-only: the package list comes from system.json, and
anything that would change packages runs into the dpkg lock that the stuck
unattended-upgrade (apt-daily-upgrade.service, also in ps) is holding.
"""

from __future__ import annotations

import fnmatch
import re

from ..engine import Ctx, Result, command
from ._util import parse_flags, stopped_pids

LOCK_SERVICE = "apt-daily-upgrade"
DPKG_LOCK = "/var/lib/dpkg/lock-frontend"
LISTS_LOCK = "/var/lib/apt/lists/lock"
MIRRORS = ["http://archive.ubuntu.com/ubuntu jammy", "http://archive.ubuntu.com/ubuntu jammy-updates",
           "http://security.ubuntu.com/ubuntu jammy-security"]
READING = "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n"
CHANGES = ("install", "reinstall", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove")
APT_WARNING = "\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n"


def _packages(ctx: Ctx) -> list[list[str]]:
    return ctx.system["packages"]


def _find(ctx: Ctx, name: str) -> list[str] | None:
    return next((p for p in _packages(ctx) if p[0] == name.split(":")[0]), None)


def _match(ctx: Ctx, patterns: list[str]) -> list[list[str]]:
    if not patterns:
        return _packages(ctx)
    return [p for p in _packages(ctx) if any(fnmatch.fnmatchcase(p[0], pat) for pat in patterns)]


def _holder(ctx: Ctx) -> tuple[int, str] | None:
    """(pid, name) of whoever holds the dpkg lock, or None once it's stopped or killed."""
    svc = ctx.system["services"].get(LOCK_SERVICE)
    if not svc or svc["pid"] in stopped_pids(ctx):
        return None
    return svc["pid"], svc["main"]


def _suite(version: str) -> str:
    # point releases like 6ubuntu14.4 or 0ubuntu0.22.04.1 came after jammy shipped
    return "jammy-updates,jammy-security" if re.search(r"ubuntu\d+\.\d|~22\.04", version) else "jammy"


def _dpkg_lock(ctx: Ctx) -> Result | None:
    if not ctx.state.is_root:
        return Result(err=f"E: Could not open lock file {DPKG_LOCK} - open (13: Permission denied)\n"
                          f"E: Unable to acquire the dpkg frontend lock ({DPKG_LOCK}), are you root?\n", code=100)
    held = _holder(ctx)
    if held:
        pid, name = held
        return Result(err=f"E: Could not get lock {DPKG_LOCK}. It is held by process {pid} ({name})\n"
                          "N: Be aware that removing the lock file is not a solution and may break your system.\n"
                          f"E: Unable to acquire the dpkg frontend lock ({DPKG_LOCK}), is another process using it?\n", code=100)
    return None


def _update(ctx: Ctx) -> Result:
    if not ctx.state.is_root:
        return Result("Reading package lists... Done\n",
                      f"E: Could not open lock file {LISTS_LOCK} - open (13: Permission denied)\n"
                      "E: Unable to lock directory /var/lib/apt/lists/\n", 100)
    # the lists lock is free; the mirrors are what's unreachable
    out, warn = [], []
    for i, mirror in enumerate(MIRRORS, 1):
        out.append(f"Ign:{i} {mirror} InRelease")
    for i, mirror in enumerate(MIRRORS, 1):
        host = mirror.split("/")[2]
        out.append(f"Err:{i} {mirror} InRelease\n  Temporary failure resolving '{host}'")
        warn.append(f"W: Failed to fetch {mirror.replace(' ', '/dists/')}/InRelease  Temporary failure resolving '{host}'")
    warn.append("W: Some index files failed to download. They have been ignored, or old ones used instead.")
    return Result("\n".join(out) + "\nReading package lists... Done\n", "\n".join(warn) + "\n")


def _change(ctx: Ctx, verb: str, names: list[str], yes: bool) -> Result:
    locked = _dpkg_lock(ctx)
    if locked:
        return locked
    if verb in ("upgrade", "dist-upgrade", "full-upgrade", "autoremove"):
        return Result(READING + ("Calculating upgrade... Done\n" if "upgrade" in verb else "")
                      + "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
    if not names:
        return Result(READING + "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
    missing = [n for n in names if _find(ctx, n) is None]
    if missing:
        return Result(READING, f"E: Unable to locate package {missing[0]}\n", 100)
    if verb in ("install", "reinstall"):
        lines = [f"{n} is already the newest version ({_find(ctx, n)[1]})." for n in names]
        return Result(READING + "\n".join(lines) + "\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
    text = READING + "The following packages will be REMOVED:\n  " + " ".join(names) + "\n"
    text += f"0 upgraded, 0 newly installed, {len(names)} to remove and 0 not upgraded.\n"
    if not yes:
        return Result(text + "Do you want to continue? [Y/n] Abort.\n", code=1)
    return Result(text, "E: Sub-process /usr/bin/dpkg returned an error code (1)\n", 100)


def _apt_list(ctx: Ctx, flags: dict, patterns: list[str]) -> Result:
    if flags.get("upgradable"):
        return Result("Listing... Done\n")
    rows = [f"{name}/{_suite(ver)},now {ver} {arch} [installed]" for name, ver, arch, _ in _match(ctx, patterns)]
    return Result("Listing... Done\n" + "".join(r + "\n" for r in rows))


def _apt_common(ctx: Ctx, args: list[str]) -> tuple[str, list[str], dict]:
    flags, pos = parse_flags(args, with_value="o")
    verb = pos[0] if pos else ""
    return verb, pos[1:], flags


@command("apt-get")
def apt_get(ctx: Ctx, args: list[str]) -> Result:
    verb, names, flags = _apt_common(ctx, args)
    if not verb:
        return Result("apt 2.4.12 (amd64)\nUsage: apt-get [options] command\n       apt-get [options] install|remove pkg1 [pkg2 ...]\n", code=1)
    if verb == "update":
        return _update(ctx)
    if verb in CHANGES:
        return _change(ctx, verb, names, bool(flags.get("y") or flags.get("yes") or flags.get("assume-yes")))
    if verb in ("clean", "autoclean", "check"):
        return Result(READING if verb == "check" else "")
    return Result(err=f"E: Invalid operation {verb}\n", code=100)


@command("apt")
def apt(ctx: Ctx, args: list[str]) -> Result:
    verb, rest, flags = _apt_common(ctx, args)
    warn = APT_WARNING if not ctx.state.tty else ""
    if not verb:
        return Result("apt 2.4.12 (amd64)\nUsage: apt [options] command\n\nMost used commands:\n  list - list packages based on package names\n"
                      "  search - search in package descriptions\n  show - show package details\n  install - install packages\n"
                      "  remove - remove packages\n  update - update list of available packages\n  upgrade - upgrade the system by installing/upgrading packages\n")
    if verb == "list":
        res = _apt_list(ctx, flags, rest)
        return Result(res.out, warn)
    if verb == "search":
        terms = [t.lower() for t in rest]
        hits = [p for p in _packages(ctx) if all(t in (p[0] + " " + p[3]).lower() for t in terms)]
        body = "".join(f"{n}/{_suite(v)},now {v} {a} [installed]\n  {d}\n\n" for n, v, a, d in hits)
        return Result("Sorting... Done\nFull Text Search... Done\n" + body, warn)
    if verb == "show":
        found = [_find(ctx, n) for n in rest]
        if not rest or None in found:
            missing = rest[found.index(None)] if rest else ""
            return Result(err=warn + f"N: Unable to locate package {missing}\nE: No packages found\n", code=100)
        blocks = [f"Package: {n}\nVersion: {v}\nPriority: optional\nArchitecture: {a}\nAPT-Manual-Installed: yes\n"
                  f"APT-Sources: /var/lib/dpkg/status\nDescription: {d}\n" for n, v, a, d in found]
        return Result("\n".join(blocks) + "\n", warn)
    if verb == "update":
        res = _update(ctx)
        return Result(res.out, warn + res.err, res.code)
    if verb in CHANGES:
        res = _change(ctx, verb, rest, bool(flags.get("y") or flags.get("yes")))
        return Result(res.out, warn + res.err, res.code)
    return Result(err=f"E: Invalid operation {verb}\n", code=100)


def _dpkg_table(rows: list[list[str]]) -> str:
    wn = max([len(r[0]) for r in rows] + [14])
    wv = max([len(r[1]) for r in rows] + [12])
    wa = max([len(r[2]) for r in rows] + [12])
    wd = max([len(r[3]) for r in rows] + [11])
    out = [
        "Desired=Unknown/Install/Remove/Purge/Hold",
        "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend",
        "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)",
        f"||/ {'Name':<{wn}} {'Version':<{wv}} {'Architecture':<{wa}} Description",
        f"+++-{'=' * wn}-{'=' * wv}-{'=' * wa}-{'=' * wd}",
    ]
    out += [f"ii  {n:<{wn}} {v:<{wv}} {a:<{wa}} {d}" for n, v, a, d in rows]
    return "\n".join(out) + "\n"


@command("dpkg", "dpkg-query")
def dpkg(ctx: Ctx, args: list[str]) -> Result:
    flags, pos = parse_flags(args)
    if flags.get("version"):
        return Result("Debian 'dpkg' package management program version 1.21.1 (amd64).\n"
                      "This is free software; see the GNU General Public License version 2 or\nlater for copying conditions. There is NO warranty.\n")
    if flags.get("l") or flags.get("list"):
        rows = _match(ctx, pos)
        if not rows:
            return Result(err=f"dpkg-query: no packages found matching {pos[0]}\n", code=1)
        return Result(_dpkg_table(rows))
    if flags.get("s") or flags.get("status"):
        if not pos:
            return Result(err="dpkg-query: error: --status needs at least one package name argument\n", code=2)
        out, err = [], []
        for name in pos:
            p = _find(ctx, name)
            if p is None:
                err.append(f"dpkg-query: package '{name}' is not installed and no information is available")
                continue
            out.append(f"Package: {p[0]}\nStatus: install ok installed\nPriority: optional\nArchitecture: {p[2]}\n"
                       f"Version: {p[1]}\nDescription: {p[3]}\n")
        if err:
            err.append("Use dpkg --info (= dpkg-deb --info) to examine archive files.")
        return Result("\n".join(out), "\n".join(err) + ("\n" if err else ""), 1 if err else 0)
    if flags.get("get-selections"):
        return Result("".join(f"{p[0]:<48}install\n" for p in _match(ctx, pos)))
    if any(flags.get(k) for k in ("i", "install", "r", "remove", "P", "purge", "configure", "unpack")):
        if not ctx.state.is_root:
            return Result(err="dpkg: error: requested operation requires superuser privilege\n", code=2)
        held = _holder(ctx)
        if held:
            return Result(err=f"dpkg: error: dpkg frontend lock was locked by another process with pid {held[0]}\n"
                              "Note: removing the lock file is always wrong, can damage the locked area\n"
                              "and the entire system. See <https://wiki.debian.org/Teams/Dpkg/FAQ#db-lock>.\n", code=2)
        if flags.get("i") or flags.get("install") or flags.get("unpack"):
            if not pos:
                return Result(err="dpkg: error: --install needs at least one package archive file argument\n", code=2)
            deb = pos[0]
            if not ctx.fs.exists(ctx.path(deb)):
                return Result(err=f"dpkg: error: cannot access archive '{deb}': No such file or directory\n", code=2)
            return Result(err=f"dpkg-deb: error: '{deb}' is not a Debian format archive\n"
                              f"dpkg: error processing archive {deb} (--install):\n"
                              " dpkg-deb --control subprocess returned error exit status 2\n"
                              f"Errors were encountered while processing:\n {deb}\n", code=1)
        if flags.get("configure"):
            return Result()
        name = pos[0] if pos else ""
        if _find(ctx, name) is None:
            return Result(err=f"dpkg: warning: ignoring request to remove {name} which isn't installed\n")
        return Result(err=f"dpkg: error processing package {name} (--remove):\n dependency problems - not removing\n"
                          f"Errors were encountered while processing:\n {name}\n", code=1)
    return Result(err="dpkg: error: need an action option\n\nType dpkg --help for help about installing and deinstalling packages [*];\n"
                      "Use 'apt' or 'aptitude' for user-friendly package management;\n", code=2)
