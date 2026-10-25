"""the worker: redis stream "raw" in, redis stream "events" out."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict

from hacktx_contracts import parse_raw_event
from redis.exceptions import ResponseError

from . import classifier
from .commands import downloaded_files
from .output import build, derived_id, public_detail
from .privacy import ip_hash
from .session import Session, SessionStore
from .techniques import map_command
from .threat import apply, level_for_event, max_level

log = logging.getLogger(__name__)

RAW = "raw"
EVENTS = "events"
DEAD = "raw:dead"
GROUP = "brain"
DONE_PREFIX = "brain:done:"
DONE_TTL_S = 86400
EVENTS_MAXLEN = 100_000
MAX_DOWNLOADS = 50


class Brain:
    def __init__(self, redis, settings, geo, reputation=None, storyteller=None):
        self.r = redis
        self.s = settings
        self.geo = geo
        self.rep = reputation
        self.story = storyteller
        self.store = SessionStore(redis, settings.session_ttl_s)
        self.locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.tasks: set[asyncio.Task] = set()
        self.session_tasks: dict[str, set[asyncio.Task]] = defaultdict(set)

    # ---- enrichment ----

    def _new_session(self, raw: dict) -> Session:
        ip = raw["src_ip"]
        s = Session(session_id=raw["session_id"], source=raw["source"], protocol=raw["protocol"],
                    src_ip=ip, ip_hash=ip_hash(ip, self.s.ip_hash_salt))
        s.geo = self.geo.locate(ip, s.source, s.ip_hash)
        asn = self.geo.asn(ip) if s.source == "wild" else None
        if asn and asn.org:
            s.asn_org, s.asn_category = asn.org, asn.category
            if asn.category == "scanner":
                # research scanners lean harmless before any lookup
                s.reputation = "harmless"
                s.family = asn.org[:64]
        return s

    async def handle(self, raw: dict) -> list[dict]:
        """enrich one raw event. returns the public events to emit now."""
        parse_raw_event(raw)  # raises on anything off-contract
        sid, typ = raw["session_id"], raw["type"]
        async with self.locks[sid]:
            s = await self.store.get(sid) or self._new_session(raw)
            s.observe(raw)

            techniques: list[str] = []
            line = ""
            if typ == "command":
                line = raw["detail"]["input"]
                techniques = map_command(line)
                s.techniques = sorted(set(s.techniques) | set(techniques))
            base = level_for_event(typ, line, s.downloads)
            if line:
                s.downloads = list(dict.fromkeys(s.downloads + downloaded_files(line)))[-MAX_DOWNLOADS:]
            s.threat_base = max_level(s.threat_base, base)
            s.threat = apply(s.threat, s.threat_base, s.reputation)

            verdict = classifier.score(s)
            emit_cls = classifier.should_emit(s.cls_kind, s.cls_conf, verdict)
            s.kind, s.confidence, s.reasons = verdict.kind, verdict.confidence, verdict.reasons

            out = [build(typ, s, raw["timestamp"], public_detail(raw, s, techniques), raw["event_id"])]
            if emit_cls:
                s.cls_kind, s.cls_conf = verdict.kind, verdict.confidence
                out.append(build("classified", s, raw["timestamp"], {"reasons": verdict.reasons},
                                 derived_id(raw["event_id"], "classified")))
            await self.store.save(s)

        self._schedule_followups(s, raw)
        return out

    def _schedule_followups(self, s: Session, raw: dict) -> None:
        if self.rep is not None:
            for target in self.rep.targets(s, raw):
                self._spawn(s.session_id, self._lookup(s.session_id, target, raw))
        if self.story is not None and raw["type"] == "session_end":
            self._spawn(s.session_id, self._tell(s.session_id, raw), track=False)

    def _spawn(self, sid: str, coro, track: bool = True) -> asyncio.Task:
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)
        if track:
            self.session_tasks[sid].add(t)
            t.add_done_callback(lambda done: self.session_tasks.get(sid, set()).discard(done))
        return t

    async def _lookup(self, sid: str, target, raw: dict) -> None:
        try:
            ev = await self.rep.run(self, sid, target, raw)
            if ev:
                await self.emit(ev)
        except Exception:
            log.exception("lookup failed for %s", sid)

    async def _tell(self, sid: str, raw: dict) -> None:
        try:
            pending = [t for t in self.session_tasks.get(sid, ()) if not t.done()]
            if pending:
                await asyncio.wait(pending, timeout=10)
            ev = await self.story.run(self, sid, raw)
            if ev:
                await self.emit(ev)
        except Exception:
            log.exception("story failed for %s", sid)
        finally:
            self.session_tasks.pop(sid, None)
            self.locks.pop(sid, None)

    async def wait_idle(self, timeout: float = 15) -> None:
        """wait for background lookups and stories (tests and shutdown)."""
        while self.tasks:
            done, _ = await asyncio.wait(set(self.tasks), timeout=timeout)
            if not done:
                break

    # ---- streams ----

    async def emit(self, ev: dict) -> None:
        await self.r.xadd(EVENTS, {"data": json.dumps(ev)}, maxlen=EVENTS_MAXLEN, approximate=True)

    async def ensure_group(self) -> None:
        try:
            await self.r.xgroup_create(RAW, GROUP, id="0", mkstream=True)
        except ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def _dead(self, msg_id, data, why: str) -> None:
        log.warning("dead-lettering %s: %s", msg_id, why)
        await self.r.xadd(DEAD, {"data": data if isinstance(data, (str, bytes)) else "", "why": why[:500]},
                          maxlen=10_000, approximate=True)

    async def process(self, msg_id, fields: dict) -> None:
        data = fields.get(b"data", fields.get("data"))
        try:
            raw = json.loads(data)
            if not isinstance(raw, dict):
                raise ValueError("not an object")
        except Exception as e:
            await self._dead(msg_id, data or "", f"bad json: {e}")
            await self.r.xack(RAW, GROUP, msg_id)
            return
        eid = raw.get("event_id")
        done_key = f"{DONE_PREFIX}{eid}"
        if eid and await self.r.exists(done_key):
            await self.r.xack(RAW, GROUP, msg_id)
            return
        try:
            outs = await self.handle(raw)
        except Exception as e:
            # off-contract input or a bug: park it so the stream keeps moving
            log.exception("failed to handle %s", msg_id)
            await self._dead(msg_id, data, f"{type(e).__name__}: {e}")
            await self.r.xack(RAW, GROUP, msg_id)
            return
        for ev in outs:
            await self.emit(ev)
        if eid:
            await self.r.set(done_key, 1, ex=DONE_TTL_S)
        await self.r.xack(RAW, GROUP, msg_id)

    async def step(self, start: str = ">", count: int = 50, block_ms: int | None = None) -> int:
        """read and process one batch. start "0" re-reads our own pending entries."""
        resp = await self.r.xreadgroup(GROUP, self.s.consumer, {RAW: start}, count=count, block=block_ms)
        n = 0
        for _stream, entries in resp or []:
            for msg_id, fields in entries:
                await self.process(msg_id, fields)
                n += 1
        return n

    async def drain_pending(self) -> int:
        """after a restart, finish whatever we read but never acked."""
        total = 0
        while True:
            n = await self.step("0")
            total += n
            if n == 0:
                return total

    async def run(self) -> None:
        await self.ensure_group()
        recovered = await self.drain_pending()
        if recovered:
            log.info("recovered %d pending events", recovered)
        log.info("brain consuming %s as %s/%s", RAW, GROUP, self.s.consumer)
        try:
            while True:
                await self.step(">", block_ms=5000)
        finally:
            await self.wait_idle(timeout=5)
