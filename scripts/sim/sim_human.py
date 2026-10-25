"""a person poking around our own trap by hand: typed key by key with uneven
delays, a typo fixed with backspace, one left in, wandering with cd and ls,
reading history and config files.

    python scripts/sim/sim_human.py            # ~2 minutes
    python scripts/sim/sim_human.py --short    # 4 plain commands, like a quick look

logs in as TEAM_SSH_USER, so every session is source=team.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import time

import common

# what a person on ubuntu sends
CLIENT = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
BS = "\x7f"

# (seconds of thinking before typing, keys). BS is a backspace
FULL = [
    (2.5, "ls"),
    (5.0, "cat .bash_history"),
    (3.0, "history"),
    (8.0, "cd /var/www"),
    (1.5, "sl"),  # left as is, like a real slip
    (2.0, "ls"),
    (6.5, "cd /opt/app"),
    (2.0, "ls -la"),
    (14.0, "cat docker-compose.yml"),
    (4.0, "cat /etc/hostanme" + BS * 4 + "name"),
    (19.0, "cat /etc/nginx/nginx.conf"),
    (3.0, "clear"),
    (5.0, "cd ~"),
    (2.5, "ls"),
    (9.0, "uptime"),
]
# a quick, clean look around: what a real visitor typed when brain called them an agent
SHORT = [
    (3.0, "ls"),
    (6.0, "cat README.md"),
    (5.0, "whoami"),
    (4.0, "uptime"),
]


def key_delay(rng: random.Random) -> float:
    """time between keys: mostly quick, sometimes a hesitation."""
    if rng.random() < 0.08:
        return rng.uniform(0.4, 1.1)
    return rng.uniform(0.07, 0.22)


def shown(keys: str) -> str:
    """the line a terminal ends up with after backspaces."""
    out: list[str] = []
    for ch in keys:
        if ch == BS:
            if out:
                out.pop()
        else:
            out.append(ch)
    return "".join(out)


async def type_line(sh: common.Shell, keys: str, rng: random.Random) -> None:
    for i, ch in enumerate(keys):
        if ch == BS and i and keys[i - 1] != BS:
            # spot the mistake first
            await asyncio.sleep(rng.uniform(0.5, 1.2))
        await sh.type(ch)
        await asyncio.sleep(key_delay(rng) if ch != BS else rng.uniform(0.08, 0.16))
    await asyncio.sleep(rng.uniform(0.1, 0.4))
    await sh.type("\r")


async def main(short: bool = False, port: int = common.DEFAULT_PORT, seed: int | None = None,
               quiet: bool = False) -> dict:
    rng = random.Random(seed)
    steps = SHORT if short else FULL
    t0 = time.monotonic()
    async with await common.connect(port, client_version=CLIENT) as conn:
        sh = await common.Shell.open(conn, pty=True)
        for think, keys in steps:
            # jitter each pause so no two runs line up
            await asyncio.sleep(think * rng.uniform(0.7, 1.4))
            await type_line(sh, keys, rng)
            out = await sh.read_prompt()
            # the first line is the pty echoing what we typed
            body = out.partition("\n")[2].rstrip()
            if not quiet:
                print(f"$ {shown(keys)}" + (f"  (typed with {keys.count(BS)} backspaces)" if BS in keys else ""))
                if body:
                    print(body)
        await asyncio.sleep(rng.uniform(1.5, 4.0))
        await sh.close()
    took = time.monotonic() - t0
    print(f"[human] done: {len(steps)} commands in {took:.0f}s")
    return {"client": CLIENT, "took": took}


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--short", action="store_true", help="4 plain commands instead of the full wander")
    ap.add_argument("--seed", type=int, help="fix the random delays")
    ap.add_argument("--port", type=int, default=common.DEFAULT_PORT)
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()
    common.run(main(a.short, a.port, a.seed, a.quiet))


if __name__ == "__main__":
    cli()
