"""web reputation via serpapi + llm, cached in redis and tiger data for 7 days."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .budget import take
from .commands import domains, tool_names
from .llm import CapReached
from .output import build, derived_id
from .privacy import scrub_ips
from .session import Session, fmt_ts
from .threat import apply

log = logging.getLogger(__name__)

CACHE_TTL_S = 7 * 86400
REDIS_PREFIX = "brain:rep:"
MAX_LOOKUPS_PER_SESSION = 4
MAX_SOURCES = 3
REP_RANK = {"unknown": 0, "harmless": 1, "malicious": 2}

# domains not worth a search
BORING_DOMAINS = ("github.com", "githubusercontent.com", "gitlab.com", "google.com", "googleapis.com",
                  "ubuntu.com", "debian.org", "centos.org", "python.org", "pypi.org", "npmjs.org",
                  "npmjs.com", "docker.com", "docker.io", "cloudflare.com", "microsoft.com")
# reserved tlds (rfc 2606) never resolve, so nothing to find
RESERVED_TLDS = (".invalid", ".test", ".example", ".localhost")
# team sessions are our own sims; worth a lookup, but stats stay wild-only
LOOKUP_SOURCES = ("wild", "team")
# tripwires where a session plainly says it's an ai agent
DECLARED_WIRES = {"agent_echo", "agent_hello"}
DECLARED_REASON = "declared itself as an AI agent"

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "reputation": {"type": "string", "enum": ["harmless", "unknown", "malicious"]},
        "family": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "summary": {"type": "string"},
        "sources": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"title": {"type": "string"}, "url": {"type": "string"}},
                "required": ["title", "url"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["reputation", "family", "summary", "sources"],
    "additionalProperties": False,
}

SYSTEM = """You judge the reputation of one indicator seen by an SSH honeypot, using only the web search results provided.

reputation:
- harmless: known research scanners (Shodan, Censys and similar), legitimate crawlers, or AI agents that declared themselves.
- malicious: tied to known botnets, malware, or abuse reports.
- unknown: anything else, including thin or unclear results. Default to unknown.

family: the botnet, malware or tool family the results name (for example "mirai" or "xmrig"), else null.
summary: one or two plain sentences on what the results say. Never include IP addresses.
sources: up to 3 results that back the verdict, with title and url copied exactly from the results."""


@dataclass(frozen=True)
class Target:
    kind: str   # ip | domain | tool
    query: str  # the string we search for
    key: str    # cache key; ips are stored only as salted hashes
    label: str  # what the llm sees


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _boring(domain: str) -> bool:
    return domain.endswith(RESERVED_TLDS) or any(domain == d or domain.endswith("." + d) for d in BORING_DOMAINS)


def stronger(current: str, new: str) -> bool:
    return REP_RANK.get(new, 0) > REP_RANK.get(current, 0)


def declare(s: Session, raw: dict) -> bool:
    """an agent that identifies itself is harmless, unless a lookup already judged it."""
    if raw["type"] != "tripwire" or raw["detail"].get("tripwire_id") not in DECLARED_WIRES:
        return False
    if s.reputation != "unknown":
        return False
    s.reputation = "harmless"
    s.dossiers = s.dossiers + [{"kind": "declared", "reputation": "harmless", "family": None,
                                "summary": DECLARED_REASON}]
    return True


class ReputationService:
    def __init__(self, redis, serp, llm, db_cache, settings):
        self.r = redis
        self.serp = serp
        self.llm = llm
        self.db = db_cache
        self.s = settings

    # ---- which lookups a session earns ----

    def eligible(self, s: Session) -> bool:
        """only spend searches on sessions that got in, tripped something or downloaded."""
        return s.source in LOOKUP_SOURCES and (s.logged_in or bool(s.tripwires) or bool(s.downloads))

    def candidates(self, s: Session, raw: dict) -> list[Target]:
        # a team ip is our own; never search it
        out = [Target("ip", f'"{s.src_ip}"', f"ip:{s.ip_hash}", "the attacking ip")] if s.source == "wild" else []
        if raw["type"] == "command":
            line = raw["detail"]["input"]
            for d in domains(line):
                if d != s.src_ip and not _boring(d):
                    out.append(Target("domain", f'"{d}"', f"domain:{_sha(d)}", d))
            # only programs it ran, chmodded +x or downloaded, with names worth searching
            for t in tool_names(line):
                out.append(Target("tool", f'"{t}" linux malware', f"tool:{_sha(t.lower())}", t))
        return out

    def targets(self, s: Session, raw: dict) -> list[Target]:
        """new lookups for this event. marks them on the session so they never repeat."""
        if self.serp is None or not self.eligible(s):
            return []
        room = MAX_LOOKUPS_PER_SESSION - len(s.lookups_done)
        picked: list[Target] = []
        for t in self.candidates(s, raw):
            if room <= 0:
                break
            if t.key in s.lookups_done or any(p.key == t.key for p in picked):
                continue
            picked.append(t)
            room -= 1
        s.lookups_done = s.lookups_done + [t.key for t in picked]
        return picked

    # ---- lookup with caches ----

    async def _cache_get(self, key: str) -> dict | None:
        hit = await self.r.get(REDIS_PREFIX + key)
        if hit:
            return json.loads(hit)
        if self.db is not None:
            try:
                row = await self.db.get(key)
            except Exception:
                log.exception("tiger cache read failed")
                row = None
            if row:
                result, created = row
                age = (datetime.now(timezone.utc) - created).total_seconds()
                ttl = int(CACHE_TTL_S - age)
                if ttl > 0:
                    await self.r.set(REDIS_PREFIX + key, json.dumps(result), ex=ttl)
                    return result
        return None

    async def _cache_put(self, target: Target, result: dict) -> None:
        await self.r.set(REDIS_PREFIX + target.key, json.dumps(result), ex=CACHE_TTL_S)
        if self.db is not None:
            try:
                await self.db.put(target.key, target.kind, result)
            except Exception:
                log.exception("tiger cache write failed")

    async def lookup(self, target: Target, src_ip: str = "", asn_org: str | None = None) -> dict | None:
        """cached verdict, or a fresh search + judgement. None if capped or failed."""
        cached = await self._cache_get(target.key)
        if cached is not None:
            return cached
        if not await take(self.r, "serpapi", self.s.serpapi_hourly_cap):
            log.info("serpapi hourly cap reached, skipping %s lookup", target.kind)
            return None
        try:
            results = await self.serp.search(target.query)
        except Exception:
            log.exception("serpapi search failed")
            return None
        results = self._clean_results(results, src_ip)
        verdict = await self._judge(target, results, asn_org)
        await self._cache_put(target, verdict)
        return verdict

    @staticmethod
    def _clean_results(results: list[dict], src_ip: str) -> list[dict]:
        """hide the attacker ip from the llm and drop links that contain it."""
        out = []
        for r in results:
            link = r.get("link", "")
            if not link.startswith(("http://", "https://")):
                continue
            if src_ip and src_ip in link:
                continue
            out.append({
                "title": scrub_ips(r.get("title", ""))[:200],
                "link": link,
                "snippet": (r.get("snippet", "").replace(src_ip, "[the ip]") if src_ip else r.get("snippet", ""))[:400],
            })
        return out

    async def _judge(self, target: Target, results: list[dict], asn_org: str | None) -> dict:
        fallback = self._fallback(target, results)
        if self.llm is None or not results:
            return fallback
        listing = "\n\n".join(f"{i}. {r['title']}\n{r['link']}\n{r['snippet']}" for i, r in enumerate(results, 1))
        user = (f"Indicator type: {target.kind}\nIndicator: {target.label}\n"
                f"Network owner: {asn_org or 'unknown'}\n\nSearch results:\n{listing}")
        try:
            text = await self.llm.complete(SYSTEM, user, VERDICT_SCHEMA)
        except CapReached:
            log.info("llm cap reached, dossier without verdict")
            return fallback
        except Exception:
            log.exception("llm judgement failed")
            return fallback
        return self.parse_verdict(text, results, fallback)

    @staticmethod
    def _fallback(target: Target, results: list[dict]) -> dict:
        noun = {"ip": "address", "domain": "domain", "tool": "tool"}[target.kind]
        if results:
            summary = f"Found {len(results)} web results for this {noun}, no verdict yet."
        else:
            summary = f"No web results for this {noun}."
        return {"reputation": "unknown", "family": None, "summary": summary,
                "sources": [{"title": r["title"] or r["link"], "url": r["link"]} for r in results[:MAX_SOURCES]]}

    @staticmethod
    def parse_verdict(text: str, results: list[dict], fallback: dict) -> dict:
        """defensive parse: bad fields fall back, sources must be real search results."""
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return fallback
        rep = data.get("reputation")
        rep = rep if rep in REP_RANK else "unknown"
        family = data.get("family")
        if not isinstance(family, str) or family.strip().lower() in ("", "null", "none", "unknown"):
            family = None
        else:
            family = family.strip()[:64]
        summary = data.get("summary")
        summary = scrub_ips(summary.strip())[:400] if isinstance(summary, str) and summary.strip() else fallback["summary"]
        links = {r["link"]: r for r in results}
        sources = []
        for src in data.get("sources") or []:
            if isinstance(src, dict) and src.get("url") in links:
                title = src.get("title") if isinstance(src.get("title"), str) else links[src["url"]]["title"]
                sources.append({"title": scrub_ips(title)[:200] or src["url"], "url": src["url"]})
            if len(sources) >= MAX_SOURCES:
                break
        if not sources:
            sources = fallback["sources"]
        return {"reputation": rep, "family": family, "summary": summary, "sources": sources}

    # ---- called by the worker in the background ----

    async def run(self, brain, sid: str, target: Target, raw: dict) -> dict | None:
        s = await brain.store.get(sid)
        if s is None:
            return None
        verdict = await self.lookup(target, s.src_ip, s.asn_org)
        if verdict is None:
            return None
        async with brain.locks[sid]:
            s = await brain.store.get(sid)
            if s is None:
                return None
            if stronger(s.reputation, verdict["reputation"]):
                s.reputation = verdict["reputation"]
                s.family = verdict["family"] or s.family
            elif verdict["reputation"] == s.reputation and verdict["family"] and not s.family:
                s.family = verdict["family"]
            s.threat = apply(s.threat, s.threat_base, s.reputation)
            s.dossiers = s.dossiers + [{"kind": target.kind, "reputation": verdict["reputation"],
                                        "family": verdict["family"], "summary": verdict["summary"]}]
            sources = [x for x in verdict["sources"] if not (s.src_ip and s.src_ip in x["url"] + x["title"])]
            ev = build("dossier", s, fmt_ts(time.time()),
                       {"summary": verdict["summary"], "sources": sources},
                       derived_id(raw["event_id"], f"dossier:{target.key}"))
            await brain.store.save(s)
        return ev
