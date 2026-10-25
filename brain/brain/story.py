"""storybook narration for a finished session."""

from __future__ import annotations

import logging
import re
import time

from .commands import downloaded_files
from .llm import CapReached
from .output import build, derived_id
from .privacy import mask_ip, scrub_ips
from .session import Session, fmt_ts
from .techniques import map_command
from .threat import level_for_command, payload_writes

log = logging.getLogger(__name__)

CREATURES = {"bot": "clay golem", "human": "dark mage", "agent": "fae", "unknown": "shadowy stranger"}
MALICIOUS = {"bot": "stone golem", "human": "evil witch", "agent": "cursed fae"}
# what the creature really is, shown in parentheses after its first mention
LABELS = {"bot": "bot", "human": "human", "agent": "AI agent", "unknown": "unknown"}
ALL_CREATURES = set(CREATURES.values()) | set(MALICIOUS.values()) | {"slime", "dragon"}

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
MAX_NOTABLE = 6
FIRST_COMMANDS = 4
# plain looking around; anything else a command maps to makes it notable
RECON = {"T1033", "T1082", "T1083", "T1057", "T1049", "T1016"}

# a story that says a session never got in, for one that did
NEVER_IN = re.compile(
    r"never (?:got|made it|slipped|broke|squeezed|crept) (?:past|in\b|inside|through)|"
    r"(?:could ?n[o']t|did ?n[o']t|failed to|unable to) (?:get|break|make it|slip|squeeze) (?:in\b|inside|past|through)|"
    r"never (?:tripped|cracked|guessed|passed|got past) (?:a single |the |any )?(?:login|password)|"
    r"gate held|locked out|stayed outside|turned away at the (?:gate|door)",
    re.I,
)
# a story that says a session got in, for one that never did
GOT_IN = re.compile(
    r"(?:got|slipped|made it|broke|crept|squeezed|wandered|stepped|sneaked|snuck) (?:inside|in(?:to)? the box)|"
    r"inside the box|\bran (?:\d+|a few|some|several) commands?",
    re.I,
)
RAN_N = re.compile(r"\bran (\d+) commands?", re.I)

SYSTEM = """You narrate honeypot sessions as tiny storybook tales for a live 3D globe.
Write 2 to 4 sentences of plain prose. Refer to the attacker as the creature you are given, and mention where it came from.
The first time you name the creature, put the label you are given right after it in parentheses. For example, with the made-up creature "moss troll" and label "(example)": "A moss troll (example) stomped in from Reykjavik". Always use the creature and label you are given, never another one.
Be playful, but stay true to the facts: do not invent actions, tools or outcomes that are not listed. Say whether it got in exactly as the login line says.
Never include IP addresses, passwords or full URLs. No titles, no lists, no quotes around the story."""


def creature(attacker: dict) -> str:
    if attacker.get("threat") == "critical":
        return "dragon"
    if attacker.get("reputation") == "harmless":
        return "slime"
    kind = attacker.get("kind", "unknown")
    if attacker.get("reputation") == "malicious" and kind in MALICIOUS:
        return MALICIOUS[kind]
    return CREATURES.get(kind, "shadowy stranger")


def label(attacker: dict) -> str:
    return LABELS.get(attacker.get("kind", "unknown"), "unknown")


def tag(text: str, who: str, what: str) -> str:
    """make sure the first mention of the creature carries its label."""
    if f"({what})".lower() in text.lower():
        return text
    m = re.search(rf"\b{re.escape(who)}\b", text, re.IGNORECASE)
    if not m:
        return text
    return f"{text[:m.end()]} ({what}){text[m.end():]}"


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
    a = s.attacker()
    who = creature(a)
    article = "an" if who[0] in "aeiou" else "a"
    parts = [f"{article.capitalize()} {who} ({label(a)}) from {place(s)} came knocking at our gate."]
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


def login_line(s: Session) -> str:
    fails = s.login_fails
    tries = f"{fails} failed tr{'ies' if fails != 1 else 'y'}"
    if s.logged_in:
        return f"succeeded {'on the first try' if not fails else f'after {tries}'}, so it got inside the box"
    if fails:
        return f"never got in: {tries}, then it left"
    return "never tried to log in and never got inside"


def notable_commands(s: Session) -> list[str]:
    """commands that reached high threat or did more than look around, in order."""
    out, downloads, written = [], [], []
    for c in s.commands:
        line = c["input"]
        risky = level_for_command(line, downloads, written) in ("high", "critical")
        downloads += downloaded_files(line)
        written += payload_writes(line)
        if risky or set(map_command(line)) - RECON:
            out.append(line)
    return out[:MAX_NOTABLE]


def facts(s: Session) -> str:
    a = s.attacker()
    lines = [
        f"creature: {creature(a)} (classified as {a['kind']}, confidence {a['confidence']})",
        f"label: ({label(a)})",
        f"from: {place(s)}",
        f"visitor type: {'a guest at our hackathon table playing along' if s.source in ('guest', 'team') else 'stranger from the internet'}",
        f"login: {login_line(s)}",
        f"commands run: {s.command_count}",
        f"threat: {a['threat']}",
        f"reputation: {a['reputation']}" + (f", known as {a['family']}" if a["family"] else ""),
        f"session length: {int((s.last_ts or 0) - (s.started_at or 0))} seconds",
    ]
    if s.techniques:
        lines.append("what it was up to: " + ", ".join(TECHNIQUE_NAMES.get(t, t) for t in s.techniques))
    if s.tripwires:
        lines.append("tripwires: " + "; ".join((t.get("reasons") or [t.get("id", "")])[0] for t in s.tripwires))
    if s.commands:
        first = [_safe(c["input"], s) for c in s.commands[:FIRST_COMMANDS]]
        lines.append("first commands:\n" + "\n".join(f"- {c}" for c in first))
    notable = [_safe(c, s) for c in notable_commands(s)]
    if notable:
        lines.append("notable commands:\n" + "\n".join(f"- {c}" for c in notable))
    return "\n".join(lines)


def _safe(line: str, s: Session) -> str:
    return scrub_ips(mask_ip(line, s.src_ip))[:120]


def problem(text: str, s: Session) -> str | None:
    """why a story can't go out: a wrong creature or label, or a claim the facts contradict."""
    a = s.attacker()
    who, what = creature(a), label(a)
    low = text.lower()
    if not re.search(rf"\b{re.escape(who)}\b", low):
        return f"it never names the {who}"
    for other in sorted(ALL_CREATURES - {who}):
        # "fae" inside "cursed fae" is still our creature
        if other not in who and re.search(rf"\b{re.escape(other)}\b", low):
            return f"it calls the creature a {other}, not a {who}"
    for other in sorted(set(LABELS.values()) - {what}):
        if f"({other.lower()})" in low:
            return f"it labels the creature ({other}), not ({what})"
    if s.logged_in and NEVER_IN.search(text):
        return "it says the creature never got in, but its login succeeded"
    if not s.logged_in and GOT_IN.search(text):
        return "it says the creature got inside, but it never logged in"
    m = RAN_N.search(text)
    if m and int(m.group(1)) != s.command_count:
        return f"it says {m.group(1)} commands, but the creature ran {s.command_count}"
    return None


class Storyteller:
    def __init__(self, llm=None):
        self.llm = llm

    async def tell(self, s: Session) -> str:
        if self.llm is None:
            return template_story(s)
        a = s.attacker()
        user = facts(s)
        # one retry that says what was wrong, then the template
        for _ in range(2):
            try:
                story = clean(tag(await self.llm.complete(SYSTEM, user) or "", creature(a), label(a)))
            except CapReached:
                log.info("llm cap reached, template story")
                break
            except Exception:
                log.exception("story llm failed, template story")
                break
            why = problem(story, s) if story else "it was empty"
            if why is None:
                return story
            log.info("story for %s rejected: %s", s.session_id, why)
            user = f"{facts(s)}\n\nYour last story was rejected because {why}. Write a new one that fits the facts."
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
