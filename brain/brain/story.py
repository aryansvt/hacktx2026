"""storybook narration for a finished session."""

from __future__ import annotations

import logging
import re
import time

from .llm import CapReached
from .output import build, derived_id
from .privacy import mask_ip, scrub_ips
from .session import Session, fmt_ts

log = logging.getLogger(__name__)

CREATURES = {"bot": "robot", "human": "orc", "agent": "alien", "unknown": "shadowy stranger"}

# most notable first; stories mention the first two a session hit
TECHNIQUE_NAMES = {
    "T1496": "summoning a crypto miner", "T1070.002": "erasing the logs", "T1070.003": "wiping its shell history",
    "T1098.004": "slipping in its own ssh key", "T1053.003": "planting cron jobs", "T1136.001": "making a new account",
    "T1003.008": "grabbing password hashes", "T1552.001": "hunting for secrets in config files",
    "T1552.004": "hunting for private keys", "T1105": "fetching tools from afar", "T1140": "decoding hidden payloads",
    "T1562.004": "tampering with the firewall", "T1098": "changing passwords", "T1552.003": "reading old shell history",
    "T1059.004": "running shell scripts", "T1087.001": "reading the list of users", "T1222.002": "making files runnable",
    "T1057": "peeking at running programs", "T1049": "mapping connections", "T1016": "mapping the network",
    "T1083": "rummaging through files", "T1033": "asking who it was", "T1082": "snooping on the system",
}

MAX_STORY = 700

SYSTEM = """You narrate honeypot sessions as tiny storybook tales for a live 3D globe.
Write 2 to 4 sentences of plain prose. Refer to the attacker as the creature you are given, and mention where it came from.
Be playful, but stay true to the facts: do not invent actions, tools or outcomes that are not listed.
Never include IP addresses, passwords or full URLs. No titles, no lists, no quotes around the story."""


def creature(attacker: dict) -> str:
    if attacker.get("threat") == "critical":
        return "dragon"
    if attacker.get("reputation") == "harmless":
        return "slime"
    return CREATURES.get(attacker.get("kind", "unknown"), "shadowy stranger")


def place(s: Session) -> str:
    geo = s.geo or {}
    if s.source in ("guest", "team"):
        return "our own table in Austin"
    if geo.get("city"):
        return geo["city"]
    if geo.get("country") and geo["country"] != "XX":
        return f"somewhere in {geo['country']}"
    return "a land no map could name"


def clean(text: str) -> str:
    text = scrub_ips(text or "")
    text = re.sub(r"\s+", " ", text).strip().strip('"').strip()
    return text[:MAX_STORY]


def _sentences(parts: list[str]) -> str:
    return " ".join(parts[:4])


def template_story(s: Session) -> str:
    """story without the llm. always 2-4 sentences."""
    who = creature(s.attacker())
    article = "an" if who[0] in "aeiou" else "a"
    parts = [f"{article.capitalize()} {who} from {place(s)} came knocking at our gate."]
    users = list(dict.fromkeys(x["username"] for x in s.logins))[:3]
    if not s.logged_in:
        tries = s.login_fails
        if tries:
            names = ", ".join(users)
            parts.append(f"It rattled the lock {tries} time{'s' if tries != 1 else ''} with names like {names}, but the gate held.")
        else:
            parts.append("It peered at the gate, thought better of it, and left.")
    else:
        n = s.command_count
        acts = [name for t, name in TECHNIQUE_NAMES.items() if t in s.techniques][:2]
        doing = f", {' and '.join(acts)}" if acts else ""
        parts.append(f"It slipped inside and ran {n} command{'s' if n != 1 else ''}{doing}.")
        if s.tripwires:
            parts.append("It took the bait we left out and tripped a hidden wire.")
        elif s.downloads:
            parts.append(f"It tried to fetch {s.downloads[0]} from afar, but nothing real ever arrived.")
    if s.reputation == "malicious" and s.family:
        parts.append(f"The scrolls name it kin to {s.family}.")
    parts.append("Then it vanished back into the night.")
    if len(parts) > 4:
        parts = parts[:3] + [parts[-1]]
    return _sentences(parts)


def facts(s: Session) -> str:
    a = s.attacker()
    lines = [
        f"creature: {creature(a)} (classified as {a['kind']}, confidence {a['confidence']})",
        f"from: {place(s)}",
        f"visitor type: {'a guest at our hackathon table playing along' if s.source in ('guest', 'team') else 'stranger from the internet'}",
        f"how far it got: {s.status if not s.logged_in else 'inside the box'}",
        f"failed logins: {s.login_fails}",
        f"threat: {a['threat']}",
        f"reputation: {a['reputation']}" + (f", known as {a['family']}" if a["family"] else ""),
        f"session length: {int((s.last_ts or 0) - (s.started_at or 0))} seconds",
    ]
    if s.techniques:
        lines.append("what it was up to: " + ", ".join(TECHNIQUE_NAMES.get(t, t) for t in s.techniques))
    if s.tripwires:
        lines.append("tripwires: " + "; ".join((t.get("reasons") or [t.get("id", "")])[0] for t in s.tripwires))
    if s.commands:
        cmds = [scrub_ips(mask_ip(c["input"], s.src_ip))[:120] for c in s.commands[:12]]
        lines.append("commands in order:\n" + "\n".join(f"- {c}" for c in cmds))
    return "\n".join(lines)


class Storyteller:
    def __init__(self, llm=None):
        self.llm = llm

    async def tell(self, s: Session) -> str:
        if self.llm is not None:
            try:
                story = clean(await self.llm.complete(SYSTEM, facts(s)))
                if story:
                    return story
            except CapReached:
                log.info("llm cap reached, template story")
            except Exception:
                log.exception("story llm failed, template story")
        return template_story(s)

    async def run(self, brain, sid: str, raw: dict) -> dict | None:
        s = await brain.store.get(sid)
        if s is None:
            return None
        story = await self.tell(s)
        async with brain.locks[sid]:
            s = await brain.store.get(sid) or s
            s.story = story
            ev = build("story", s, fmt_ts(time.time()), {"story": story}, derived_id(raw["event_id"], "story"))
            await brain.store.save(s)
        return ev
