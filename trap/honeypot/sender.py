"""drains the jsonl spool into core's POST /ingest.

the cursor file holds a byte offset into the spool. it only moves forward
after core accepts an event, or after an event core rejects (422/413) has
been copied to the dead letter file. anything else keeps the events and
retries with backoff, so nothing is lost while core is down.

this is the only module allowed to make outbound http, and only to CORE_URL.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

from .config import Settings
from .events import now_ts

log = logging.getLogger("honeypot.sender")

BATCH = 100
# core caps a request at 5 MB; stay far below it
BATCH_BYTES = 1 << 20
IDLE_SLEEP = 0.5
BACKOFF_MIN = 1.0
BACKOFF_MAX = 60.0
TIMEOUT = 10.0
COMPACT_BYTES = 16 << 20
# statuses that mean "this content is bad", so retrying it as is won't help
REJECT = {413, 422}
MAX_REASON = 500

IDLE, SENT, FAILED = "idle", "sent", "failed"

_BAD = object()
_BLANK = object()


class OffTarget(RuntimeError):
    """a request tried to leave for somewhere other than CORE_URL."""


@dataclass
class Line:
    end: int
    event: object


class Sender:
    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.spool_path = settings.spool_path
        self.cursor_path = settings.cursor_path
        self.dead_letter_path = settings.dead_letter_path
        self.compact_bytes = COMPACT_BYTES
        self.sleep = sleep
        self.sent = 0
        self.dead = 0
        self.failing = False
        self.retry_after: float | None = None
        self._error = ""
        self.cursor = self._load_cursor()
        if self.cursor > self._spool_size():
            self._save_cursor(0)

        self.client: httpx.AsyncClient | None = None
        url = httpx.URL(settings.core_url) if settings.core_url else None
        if url is None or not settings.ingest_token:
            log.warning("CORE_URL or INGEST_TOKEN not set, events stay in %s", self.spool_path)
            return
        if url.scheme not in ("http", "https") or not url.host:
            log.error("CORE_URL must be an http(s) url, sender is off and events stay in %s", self.spool_path)
            return
        if url.scheme == "http":
            log.warning("CORE_URL is plain http, use https outside local dev")
        self._origin = (url.scheme, url.host, url.port)
        self.client = httpx.AsyncClient(
            base_url=url,
            transport=transport,
            headers={"Authorization": f"Bearer {settings.ingest_token}"},
            timeout=TIMEOUT,
            # no redirects and no proxy env vars, so nothing can reroute us
            follow_redirects=False,
            trust_env=False,
            event_hooks={"request": [self._guard]},
        )

    @property
    def enabled(self) -> bool:
        return self.client is not None

    async def close(self) -> None:
        if self.client is not None:
            await self.client.aclose()

    async def run(self) -> None:
        delay = BACKOFF_MIN
        while True:
            try:
                result = await self.step()
            except Exception:
                log.exception("sender step crashed, retrying")
                self.retry_after = None
                result = FAILED
            if result == SENT:
                delay = BACKOFF_MIN
                continue
            if result == IDLE:
                await self.sleep(IDLE_SLEEP)
                continue
            if self.retry_after is not None:
                await self.sleep(self.retry_after)
            else:
                await self.sleep(delay * random.uniform(0.75, 1.0))
                delay = min(delay * 2, BACKOFF_MAX)

    async def step(self) -> str:
        """send one batch. returns idle, sent or failed."""
        batch = self._read_batch()
        if not batch:
            self._maybe_compact()
            return IDLE
        resp = await self._post([line.event for line in batch])
        if _ok(resp):
            self._accepted(batch[-1].end, len(batch))
            return SENT
        if resp is not None and resp.status_code in REJECT:
            if len(batch) == 1:
                self._reject(batch[0], resp)
                return SENT
            return await self._one_by_one(batch)
        return self._failed(resp)

    async def _one_by_one(self, batch: list[Line]) -> str:
        """core rejected the batch; find the bad events so the rest still go."""
        for line in batch:
            resp = await self._post([line.event])
            if _ok(resp):
                self._accepted(line.end, 1)
            elif resp is not None and resp.status_code in REJECT:
                self._reject(line, resp)
            else:
                return self._failed(resp)
        return SENT

    async def _post(self, events: list) -> httpx.Response | None:
        assert self.client is not None
        try:
            return await self.client.post("/ingest", json=events)
        except httpx.HTTPError as e:
            self._error = type(e).__name__
            return None

    async def _guard(self, request: httpx.Request) -> None:
        if (request.url.scheme, request.url.host, request.url.port) != self._origin:
            raise OffTarget("refusing a request that is not for CORE_URL")

    def _accepted(self, end: int, n: int) -> None:
        self._save_cursor(end)
        self.sent += n
        if self.failing:
            log.info("core is taking events again")
            self.failing = False

    def _reject(self, line: Line, resp: httpx.Response) -> None:
        self._dead_letter(line.event, resp.status_code, resp.text)
        self._save_cursor(line.end)

    def _failed(self, resp: httpx.Response | None) -> str:
        self.retry_after = _retry_after(resp) if resp is not None and resp.status_code == 429 else None
        if not self.failing:
            why = f"status {resp.status_code}" if resp is not None else self._error
            log.warning("core is not taking events (%s), keeping them and retrying", why)
            self.failing = True
        return FAILED

    def _read_batch(self) -> list[Line]:
        size = self._spool_size()
        if self.cursor > size:
            # spool was truncated under us
            self._save_cursor(0)
        if self.cursor == size:
            return []
        batch: list[Line] = []
        nbytes = 0
        with self.spool_path.open("rb") as f:
            f.seek(self.cursor)
            pos = self.cursor
            while len(batch) < BATCH and nbytes < BATCH_BYTES:
                raw = f.readline()
                # eof, or a line the sink hasn't finished writing
                if not raw.endswith(b"\n"):
                    break
                end = pos + len(raw)
                event = _parse(raw)
                if event is _BAD or event is _BLANK:
                    # keep order: send what we have before skipping past it
                    if batch:
                        break
                    if event is _BAD:
                        self._dead_letter(raw.decode("utf-8", "replace").rstrip("\r\n"), None, "not json")
                    self._save_cursor(end)
                else:
                    batch.append(Line(end, event))
                    nbytes += len(raw)
                pos = end
        return batch

    def _maybe_compact(self) -> None:
        """once everything is sent, start the spool over so it can't fill the disk."""
        if self.cursor >= self.compact_bytes and self.cursor == self._spool_size():
            # truncate first: a crash in between leaves cursor > size, which resets to 0
            self.spool_path.open("wb").close()
            self._save_cursor(0)

    def _dead_letter(self, event: object, status: int | None, reason: str) -> None:
        record = {"rejected_at": now_ts(), "status": status, "reason": reason[:MAX_REASON], "event": event}
        self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
        with self.dead_letter_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
        self.dead += 1
        log.warning("core rejected an event (%s), moved it to %s", status or reason, self.dead_letter_path)

    def _spool_size(self) -> int:
        try:
            return self.spool_path.stat().st_size
        except FileNotFoundError:
            return 0

    def _load_cursor(self) -> int:
        try:
            return max(0, int(self.cursor_path.read_text(encoding="utf-8").strip() or 0))
        except (FileNotFoundError, ValueError):
            return 0

    def _save_cursor(self, offset: int) -> None:
        self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cursor_path.with_name(self.cursor_path.name + ".tmp")
        tmp.write_text(str(offset), encoding="utf-8")
        os.replace(tmp, self.cursor_path)
        self.cursor = offset


def _parse(raw: bytes) -> object:
    body = raw.strip()
    if not body:
        return _BLANK
    try:
        return json.loads(body)
    except ValueError:
        return _BAD


def _ok(resp: httpx.Response | None) -> bool:
    return resp is not None and 200 <= resp.status_code < 300


def _retry_after(resp: httpx.Response) -> float | None:
    try:
        return min(max(float(resp.headers.get("retry-after", "")), 0.0), BACKOFF_MAX)
    except ValueError:
        return None
