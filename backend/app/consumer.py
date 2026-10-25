"""reads brain's public events from redis stream "events", persists, broadcasts, acks."""

import asyncio
import json
import logging
from typing import Any

from hacktx_contracts import parse_event
from pydantic import ValidationError
from redis.exceptions import ResponseError

from .live import Hub
from .store import Store

log = logging.getLogger(__name__)

STREAM = "events"
GROUP = "backend"
BATCH = 100


async def ensure_group(redis: Any) -> None:
    try:
        await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


async def handle_entry(entry_id: str, fields: dict, redis: Any, store: Store, hub: Hub) -> None:
    try:
        event = json.loads(fields["data"])
        # contract check; models forbid extra fields, so a leaked src_ip is rejected here
        parse_event(event)
    except (KeyError, ValueError, ValidationError) as e:
        log.warning("dropping invalid event %s: %s", entry_id, type(e).__name__)
        await redis.xack(STREAM, GROUP, entry_id)
        return

    try:
        await store.persist(event)
    except Exception:
        # left pending so it is retried on restart; still show it live
        log.exception("persist failed for %s", entry_id)
        hub.broadcast(json.dumps(event))
        return

    hub.broadcast(json.dumps(event))
    await redis.xack(STREAM, GROUP, entry_id)


async def run_consumer(redis: Any, store: Store, hub: Hub, name: str, block_ms: int = 5000) -> None:
    await ensure_group(redis)
    # first walk our own pending entries (from a crash), then switch to new ones
    cursor = "0"
    while True:
        try:
            block = None if cursor != ">" else block_ms
            resp = await redis.xreadgroup(GROUP, name, {STREAM: cursor}, count=BATCH, block=block)
            entries = resp[0][1] if resp else []
            if cursor != ">":
                if not entries:
                    cursor = ">"
                    continue
                cursor = entries[-1][0]
            elif not entries:
                # never spin if the server returns early from a blocking read
                await asyncio.sleep(0.05)
            for entry_id, fields in entries:
                await handle_entry(entry_id, fields, redis, store, hub)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("consumer loop error")
            await asyncio.sleep(1)
