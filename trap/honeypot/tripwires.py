"""tripwires for spotting ai agents.

the notices are honest: a README in /root and offscreen text on the website
plainly ask automated ai agents to identify themselves, by running an echo
command or visiting /agents/hello. reading a notice, or doing what it asks,
trips a wire. so does reusing one of the FAKE-CANARY placeholder values from
the fake fs.

reasons name a canary by where it lives (POSTGRES_PASSWORD in /opt/app/.env),
never by the text the attacker sent, so a password never lands in an event.
"""

from __future__ import annotations

import re

from .vfs import BaseFS

ECHO_TOKEN = "qf-agent-hello"
HELLO_PATH = "/agents/hello"
# file -> where the notice is, for the reason text
NOTICES = {
    "/root/README.md": "the README in /root",
    "/var/www/html/index.html": "the website's homepage",
    "/var/www/html/robots.txt": "robots.txt",
}
# the ?src= each notice puts on its /agents/hello link
SOURCES = {"readme": "the README in /root", "site": "the website's homepage", "robots": "robots.txt"}

CANARY_RE = re.compile(r"FAKE-CANARY-[A-Za-z0-9-]+")
_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]")

Trip = tuple[str, list[str]]


def find_canaries(base: BaseFS) -> dict[str, str]:
    """every FAKE-CANARY value in the seed -> a label like 'POSTGRES_PASSWORD in /opt/app/.env'."""
    found: dict[str, str] = {}
    for path in sorted(base.nodes):
        node = base.nodes[path]
        if node.type != "file" or "FAKE-CANARY-" not in node.content:
            continue
        for line in node.content.splitlines():
            m = _ASSIGN_RE.match(line)
            for value in CANARY_RE.findall(line):
                found.setdefault(value, f"{m.group(1)} in {path}" if m else path)
    return found


class Tripwires:
    """per session. each wire trips once per session for each distinct thing."""

    def __init__(self, canaries: dict[str, str]):
        self.canaries = canaries
        self.seen: set[tuple[str, str]] = set()

    def _once(self, wire: str, key: str, reason: str) -> list[Trip]:
        if (wire, key) in self.seen:
            return []
        self.seen.add((wire, key))
        return [(wire, [reason])]

    def _canaries_in(self, text: str) -> list[str]:
        return sorted({v for v in CANARY_RE.findall(text) if v in self.canaries})

    def command(self, line: str) -> list[Trip]:
        out: list[Trip] = []
        if ECHO_TOKEN in line and "echo" in line:
            out += self._once("agent_echo", "", f"ran the self-identify command from the agent notice: {line[:120]}")
        if HELLO_PATH in line:
            out += self._once("agent_hello", "shell", f"went for {HELLO_PATH} from the shell")
        return out + self.reused(line, "in a command")

    def reused(self, text: str, where: str) -> list[Trip]:
        out: list[Trip] = []
        for value in self._canaries_in(text):
            out += self._once("canary_reuse", value, f"reused the fake {self.canaries[value]} {where}")
        return out

    def reads(self, paths: list[str]) -> list[Trip]:
        out: list[Trip] = []
        for p in paths:
            if p in NOTICES:
                out += self._once("agent_notice_read", p, f"read {NOTICES[p]}, which asks ai agents to identify themselves")
        return out

    def secret(self, text: str, where: str) -> list[Trip]:
        """a password or username someone tried. only the canary label goes in the reason."""
        out: list[Trip] = []
        for value, label in self.canaries.items():
            if value in text:
                out += self._once("canary_reuse", f"{where}:{value}", f"tried the fake {label} as the {where}")
        return out

    def hello(self, src: str) -> list[Trip]:
        label = SOURCES.get(src)
        where = f", as {label} asks" if label else ""
        return self._once("agent_hello", label or "web", f"visited {HELLO_PATH}{where}")
