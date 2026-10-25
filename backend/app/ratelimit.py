import time
from typing import Callable

MAX_KEYS = 10_000


class TokenBucket:
    """per key token bucket. allow() returns (ok, seconds until next token)."""

    def __init__(self, rate: float, burst: int, clock: Callable[[], float] = time.monotonic):
        self.rate = rate
        self.burst = burst
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> tuple[bool, float]:
        now = self.clock()
        tokens, last = self._buckets.get(key, (float(self.burst), now))
        tokens = min(float(self.burst), tokens + (now - last) * self.rate)
        if tokens >= 1:
            self._store(key, tokens - 1, now)
            return True, 0.0
        self._store(key, tokens, now)
        return False, (1 - tokens) / self.rate

    def _store(self, key: str, tokens: float, now: float) -> None:
        if key not in self._buckets and len(self._buckets) >= MAX_KEYS:
            # keep memory bounded if something sprays us from many ips
            self._buckets.clear()
        self._buckets[key] = (tokens, now)
