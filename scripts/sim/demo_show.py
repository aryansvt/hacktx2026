"""the full cast against our own trap, one after another, with a pause between
each so the globe has time to show every creature.

    python scripts/sim/demo_show.py
    python scripts/sim/demo_show.py --gap 30 --family mirai

every act logs in as TEAM_SSH_USER, so it's all source=team and never counts in stats.
the two agent acts need ANTHROPIC_API_KEY in .env.
"""

from __future__ import annotations

import argparse
import asyncio
import time

import common
import demo_agent
import demo_escalation
import sim_bot
import sim_human

GAP_S = 20.0
FAMILY = "mirai"
BOLD, RESET = "\x1b[1m", "\x1b[0m"


def cast(family: str = FAMILY) -> list[tuple[str, str, object]]:
    """(what runs, the creature it should become, a callable that starts it)."""
    return [
        ("sim_bot", "clay golem", lambda: sim_bot.main()),
        (f"sim_bot --family {family}", "stone golem", lambda: sim_bot.main(family=family)),
        ("sim_human", "dark mage", lambda: sim_human.main()),
        ("demo_agent", "fae", lambda: demo_agent.main()),
        ("demo_agent --polite", "purple slime", lambda: demo_agent.main(polite=True)),
        ("demo_escalation", "dragon", lambda: demo_escalation.main()),
    ]


async def main(gap: float = GAP_S, family: str = FAMILY) -> list[tuple[str, str]]:
    acts = cast(family)
    print(f"{BOLD}tonight's cast{RESET}")
    for i, (name, creature, _) in enumerate(acts, 1):
        print(f"  {i}. {name:<26} -> {creature}")
    results = []
    t0 = time.monotonic()
    for i, (name, creature, start) in enumerate(acts, 1):
        if i > 1:
            print(f"\n{BOLD}next up: {name} ({creature}) in {gap:.0f}s{RESET}")
            await asyncio.sleep(gap)
        print(f"\n{BOLD}=== act {i}/{len(acts)}: {name}, watch for a {creature} ==={RESET}")
        try:
            await start()
            results.append((name, "ok"))
        except common.NotAllowed:
            raise
        except (Exception, SystemExit) as e:
            # one act failing shouldn't stop the show
            print(f"[show] {name} failed: {type(e).__name__}: {e}")
            results.append((name, "failed"))
    print(f"\n{BOLD}show done in {time.monotonic() - t0:.0f}s{RESET}")
    for name, status in results:
        print(f"  {name:<26} {status}")
    return results


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gap", type=float, default=GAP_S, help=f"seconds between acts (default {GAP_S:.0f})")
    ap.add_argument("--family", type=sim_bot.family_name, default=FAMILY, metavar="NAME",
                    help=f"botnet name for the stone golem act (default {FAMILY})")
    a = ap.parse_args()
    common.run(main(max(0.0, a.gap), a.family))


if __name__ == "__main__":
    cli()
