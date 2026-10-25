import asyncio
import time
from datetime import datetime
from typing import Any, Awaitable, Callable

from .sessions import fmt_ts

KINDS = ("bot", "human", "agent", "unknown")
REPUTATIONS = ("harmless", "unknown", "malicious")
MINUTE_KINDS = ("bot", "human", "agent")


def build_stats(raw: dict[str, Any]) -> dict[str, Any]:
    """turn store aggregates into the stats contract: zero fill and pivot per minute rows."""
    by_kind = {k: 0 for k in KINDS}
    for kind, n in raw["by_kind"].items():
        # anything brain invents that we don't know counts as unknown
        key = kind if kind in by_kind else "unknown"
        by_kind[key] += int(n)

    by_rep = {r: 0 for r in REPUTATIONS}
    for rep, n in raw["by_reputation"].items():
        key = rep if rep in by_rep else "unknown"
        by_rep[key] += int(n)

    buckets: dict[datetime, dict[str, Any]] = {}
    for minute, kind, n in raw["per_minute"]:
        if kind not in MINUTE_KINDS:
            continue
        bucket = buckets.setdefault(minute, {"t": fmt_ts(minute), "bot": 0, "human": 0, "agent": 0})
        bucket[kind] += int(n)

    return {
        "total_sessions": int(raw["total"]),
        "active_now": int(raw["active"]),
        "countries": int(raw["countries"]),
        "breaches": int(raw["breaches"]),
        "by_kind": by_kind,
        "by_reputation": by_rep,
        "per_minute": [buckets[t] for t in sorted(buckets)],
    }


class TTLCache:
    """caches one async value for ttl seconds. concurrent callers share one refresh."""

    def __init__(self, ttl: float, clock: Callable[[], float] = time.monotonic):
        self.ttl = ttl
        self.clock = clock
        self._value: Any = None
        self._expires = 0.0
        self._lock = asyncio.Lock()

    async def get(self, load: Callable[[], Awaitable[Any]]) -> Any:
        if self.clock() < self._expires:
            return self._value
        async with self._lock:
            if self.clock() < self._expires:
                return self._value
            self._value = await load()
            self._expires = self.clock() + self.ttl
            return self._value
