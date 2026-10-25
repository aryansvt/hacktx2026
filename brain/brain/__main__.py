"""python -m brain"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

import redis.asyncio as aioredis

from .cache_db import PgReputationCache
from .config import Settings
from .geo import GeoLocator
from .llm import make_llm
from .reputation import ReputationService
from .serpapi import SerpApi
from .story import Storyteller
from .worker import Brain

log = logging.getLogger("brain")


async def main() -> None:
    s = Settings.from_env()
    if not s.ip_hash_salt:
        # an unsalted ipv4 hash is trivial to reverse
        log.error("IP_HASH_SALT is empty, refusing to start")
        sys.exit(2)

    # socket timeout must outlast the 5s blocking xreadgroup
    r = aioredis.from_url(s.redis_url, socket_timeout=30, health_check_interval=30)
    geo = GeoLocator.from_settings(s)
    llm = make_llm(s, r)

    db = None
    if s.database_url:
        db = PgReputationCache(s.database_url)
        try:
            await db.start()
        except Exception:
            log.exception("tiger data unavailable, reputation cache is redis only")
            db = None
    else:
        log.warning("TIGER_DATABASE_URL not set, reputation cache is redis only")

    serp = SerpApi(s.serpapi_key) if s.serpapi_key else None
    if serp is None:
        log.warning("SERPAPI_KEY not set, no reputation lookups")

    brain = Brain(r, s, geo, reputation=ReputationService(r, serp, llm, db, s), storyteller=Storyteller(llm, reserved=llm.ours() if llm else None))

    task = asyncio.create_task(brain.run())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, task.cancel)
        except (NotImplementedError, RuntimeError):
            pass  # windows dev box
    try:
        await task
    except asyncio.CancelledError:
        log.info("shutting down")
    finally:
        if serp is not None:
            await serp.close()
        if db is not None:
            await db.close()
        await r.aclose()


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
