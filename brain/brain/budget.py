"""hourly spend caps kept in redis."""

from __future__ import annotations

from datetime import datetime, timezone


def hour_key(name: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"brain:cap:{name}:{now.strftime('%Y%m%d%H')}"


async def take(redis, name: str, cap: int) -> bool:
    """count one unit against this hour's cap. false once the cap is used up."""
    if cap <= 0:
        return False
    key = hour_key(name)
    n = await redis.incr(key)
    if n == 1:
        await redis.expire(key, 7200)
    return n <= cap
