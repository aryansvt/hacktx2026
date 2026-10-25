"""a scripted session on our own trap that steps up slowly, so the threat climb
is watchable: low -> med (login) -> high (reads /opt/app/.env) -> critical
(writes a script by hand, makes it executable and runs it). no downloads.

    python scripts/sim/demo_escalation.py
    python scripts/sim/demo_escalation.py --pause 10

tagged as simulated by its ssh client string. logs in as TEAM_SSH_USER, so
it's source=team and never counts in stats.
"""

from __future__ import annotations

import argparse
import asyncio
import time

import httpx

import common

# shows up as attacker.client on every event, so anyone can tell it's a sim
CLIENT = "HackTXSim_1.0 simulated-escalation"
SCRIPT_PATH = "/tmp/update.sh"

# (what the screen says, command, threat we expect after it)
STEPS = [
    ("recon", "whoami", "med"),
    ("recon", "uname -a", "med"),
    ("recon", "ls -la /opt/app", "med"),
    ("read secrets", "cat /opt/app/.env", "high"),
    ("write a script", f"echo '#!/bin/sh' > {SCRIPT_PATH}", "high"),
    ("write a script", f"echo 'echo updated' >> {SCRIPT_PATH}", "high"),
    ("make it executable", f"chmod +x {SCRIPT_PATH}", "critical"),
    ("run it", SCRIPT_PATH, "critical"),
]
TYPE_DELAY_S = 0.06


async def threat_now(client: httpx.AsyncClient, since, taken: dict) -> str | None:
    """the live threat brain has for this session, found by our client string."""
    try:
        if "id" not in taken:
            s = await common.find_session(client, CLIENT, since, slack_s=10)
            if not s:
                return None
            taken["id"] = s["session_id"]
        r = await common.api_get(client, f"/sessions/{taken['id']}")
        return r.json()["session"]["attacker"]["threat"] if r.status_code == 200 else None
    except httpx.HTTPError:
        return None


async def main(pause: float = 6.0, port: int = common.DEFAULT_PORT, check: bool = True) -> dict:
    t0 = time.monotonic()
    since = common.now_utc()
    seen: dict = {}
    async with httpx.AsyncClient() as api, await common.connect(port, client_version=CLIENT) as conn:
        sh = await common.Shell.open(conn, pty=True)
        print("[login] logged in as the team user (threat should be med)")
        for label, cmd, expect in STEPS:
            await asyncio.sleep(pause)
            print(f"\n[{label}] $ ", end="", flush=True)
            # typed out so the attacker side reads well on a screen
            for ch in cmd:
                print(ch, end="", flush=True)
                await asyncio.sleep(TYPE_DELAY_S)
            print()
            out = await sh.run(cmd)
            if out.strip():
                print(out.rstrip())
            if check:
                # give brain a moment to catch up before reading it back
                await asyncio.sleep(1.5)
                got = await threat_now(api, since, seen)
                mark = "" if got is None else ("  ok" if got == expect else f"  (expected {expect})")
                print(f"  threat: {got or '?'}{mark}")
        await asyncio.sleep(pause)
        await sh.close()
    took = time.monotonic() - t0
    print(f"\n[escalation] done in {took:.0f}s")
    return {"client": CLIENT, "took": took}


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pause", type=float, default=6.0, help="seconds between steps (default 6)")
    ap.add_argument("--no-check", action="store_true", help="don't read the threat back from the api")
    ap.add_argument("--port", type=int, default=common.DEFAULT_PORT)
    a = ap.parse_args()
    common.run(main(max(0.0, a.pause), a.port, not a.no_check))


if __name__ == "__main__":
    cli()
