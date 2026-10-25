"""reputation cache table in tiger data (timescale postgres)."""

from __future__ import annotations

import json
import logging

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS reputation_cache (
    key        text PRIMARY KEY,
    kind       text NOT NULL,
    result     jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
)
"""


class PgReputationCache:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool = None

    async def start(self) -> None:
        import asyncpg

        self.pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=4)
        async with self.pool.acquire() as c:
            await c.execute(SCHEMA)

    async def get(self, key: str):
        """(result, created_at) if a row newer than 7 days exists."""
        row = await self.pool.fetchrow(
            "SELECT result, created_at FROM reputation_cache "
            "WHERE key = $1 AND created_at > now() - interval '7 days'", key)
        if not row:
            return None
        result = row["result"]
        return (json.loads(result) if isinstance(result, str) else result), row["created_at"]

    async def put(self, key: str, kind: str, result: dict) -> None:
        await self.pool.execute(
            "INSERT INTO reputation_cache (key, kind, result, created_at) VALUES ($1, $2, $3::jsonb, now()) "
            "ON CONFLICT (key) DO UPDATE SET kind = EXCLUDED.kind, result = EXCLUDED.result, created_at = now()",
            key, kind, json.dumps(result))

    async def close(self) -> None:
        if self.pool is not None:
            await self.pool.close()
