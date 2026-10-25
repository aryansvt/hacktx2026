import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import api, ingest
from .config import VERCEL_ORIGIN_REGEX, Settings
from .consumer import run_consumer
from .live import Hub
from .ratelimit import TokenBucket
from .stats import TTLCache
from .store import PgStore, Store

log = logging.getLogger(__name__)

CLEANUP_EVERY = 3600


async def _cleanup_loop(store: Store) -> None:
    while True:
        try:
            removed = await store.cleanup()
            if removed:
                log.info("removed %d sessions past retention", removed)
        except Exception:
            log.exception("session cleanup failed")
        await asyncio.sleep(CLEANUP_EVERY)


def create_app(settings: Settings | None = None, redis: Any = None, store: Store | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = app.state
        state.redis = redis or aioredis.from_url(settings.redis_url, decode_responses=True)
        if store is not None:
            state.store = store
        else:
            if not settings.database_url:
                raise RuntimeError("TIGER_DATABASE_URL is not set")
            state.store = PgStore(settings.database_url)
        await state.store.start()

        tasks = [
            asyncio.create_task(
                run_consumer(
                    state.redis, state.store, state.hub, settings.consumer_name, settings.consumer_block_ms
                )
            ),
            asyncio.create_task(_cleanup_loop(state.store)),
        ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await state.store.close()
            if redis is None:
                await state.redis.aclose()

    app = FastAPI(title="hacktx core", lifespan=lifespan)
    app.state.settings = settings
    app.state.hub = Hub(settings.ping_interval, settings.send_timeout, settings.client_queue_size)
    app.state.limiter = TokenBucket(settings.ingest_rate_per_sec, settings.ingest_burst)
    app.state.stats_cache = TTLCache(settings.stats_ttl)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins(),
        allow_origin_regex=VERCEL_ORIGIN_REGEX,
        allow_methods=["GET"],
        allow_headers=["*"],
    )
    app.include_router(ingest.router)
    app.include_router(api.router)
    return app


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
