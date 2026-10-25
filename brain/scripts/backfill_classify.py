"""one-time backfill: reclassify ended sessions that tiger data still has as unknown.

for each one that now classifies, writes a classified event to redis stream "events",
so the backend stores it, updates the session and broadcasts it on /live.

    TIGER_DATABASE_URL=... REDIS_URL=... python brain/scripts/backfill_classify.py --dry-run
    TIGER_DATABASE_URL=... REDIS_URL=... python brain/scripts/backfill_classify.py
"""

import argparse
import asyncio
import json
import sys

import asyncpg
import redis.asyncio as aioredis

from brain.backfill import backfill, stored_sessions
from brain.config import Settings


async def _init_conn(conn) -> None:
    for name in ("json", "jsonb"):
        await conn.set_type_codec(name, encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def main(dry_run: bool) -> int:
    s = Settings.from_env()
    if not s.database_url:
        print("TIGER_DATABASE_URL is not set", file=sys.stderr)
        return 2
    pool = await asyncpg.create_pool(s.database_url, min_size=1, max_size=2, init=_init_conn)
    r = aioredis.from_url(s.redis_url)
    try:
        counts = await backfill(stored_sessions(pool), r, dry_run=dry_run)
    finally:
        await pool.close()
        await r.aclose()
    verb = "would write" if dry_run else "wrote"
    kinds = ", ".join(f"{k} {c}" for k, c in sorted(counts["by_kind"].items())) or "none"
    print(f"checked {counts['checked']} ended unknown sessions")
    n = counts["classified"]
    print(f"{verb} {n} classified event{'' if n == 1 else 's'} ({kinds})")
    print(f"still unknown: {counts['still_unknown']}")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dry-run", action="store_true", help="only print the counts, write nothing")
    sys.exit(asyncio.run(main(p.parse_args().dry_run)))
