import asyncio
from datetime import datetime, timedelta, timezone

from app.stats import TTLCache, build_stats

from .conftest import validator

T = datetime(2026, 10, 24, 18, 0, tzinfo=timezone.utc)


def test_build_stats_zero_fills_and_pivots():
    stats = build_stats(
        {
            "total": 5,
            "active": 2,
            "countries": 3,
            "breaches": 1,
            "by_kind": {"bot": 3, "agent": 1, "weird": 1},
            "by_reputation": {"malicious": 4},
            "per_minute": [
                (T, "bot", 2),
                (T, "agent", 1),
                (T + timedelta(minutes=1), "human", 1),
                (T + timedelta(minutes=1), "unknown", 7),
            ],
        }
    )
    validator("stats").validate(stats)
    assert stats["by_kind"] == {"bot": 3, "human": 0, "agent": 1, "unknown": 1}
    assert stats["by_reputation"] == {"harmless": 0, "unknown": 0, "malicious": 4}
    assert stats["per_minute"] == [
        {"t": "2026-10-24T18:00:00.000Z", "bot": 2, "human": 0, "agent": 1},
        {"t": "2026-10-24T18:01:00.000Z", "bot": 0, "human": 1, "agent": 0},
    ]


def test_build_stats_empty():
    stats = build_stats(
        {"total": 0, "active": 0, "countries": 0, "breaches": 0, "by_kind": {}, "by_reputation": {}, "per_minute": []}
    )
    validator("stats").validate(stats)


async def test_ttl_cache_reuses_value_until_expiry():
    now = [0.0]
    cache = TTLCache(5, clock=lambda: now[0])
    calls = 0

    async def load():
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return calls

    assert await asyncio.gather(cache.get(load), cache.get(load)) == [1, 1]
    now[0] = 4.9
    assert await cache.get(load) == 1
    now[0] = 5.1
    assert await cache.get(load) == 2
