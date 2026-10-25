"""sessions per ip_hash over the last hour, in a redis sorted set (member session_id, score start time)."""

from __future__ import annotations

WINDOW_S = 3600


class VisitTracker:
    def __init__(self, redis, window_s: int = WINDOW_S, prefix: str = "brain:visits:"):
        self.r = redis
        self.window = window_s
        self.prefix = prefix

    def key(self, ip_hash: str) -> str:
        return self.prefix + ip_hash

    async def record(self, ip_hash: str, session_id: str, ts: float) -> int:
        """note a new session. returns sessions in the window ending at ts, this one included."""
        k = self.key(ip_hash)
        async with self.r.pipeline(transaction=True) as p:
            p.zadd(k, {session_id: ts}, nx=True)
            p.zremrangebyscore(k, "-inf", f"({ts - self.window}")
            p.expire(k, self.window)
            p.zcount(k, ts - self.window, ts)
            res = await p.execute()
        return int(res[-1])

    async def count(self, ip_hash: str, ts: float) -> int:
        """sessions that started in the window ending at ts."""
        return int(await self.r.zcount(self.key(ip_hash), ts - self.window, ts))
