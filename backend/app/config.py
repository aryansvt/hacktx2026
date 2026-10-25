import os
import socket
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


@dataclass(frozen=True)
class Settings:
    ingest_token: str = ""
    redis_url: str = "redis://localhost:6379/0"
    database_url: str = ""
    domain: str = "example.com"
    ingest_rate_per_sec: float = 20.0
    ingest_burst: int = 40
    ingest_max_batch: int = 500
    ingest_max_bytes: int = 5 * 1024 * 1024
    ping_interval: float = 20.0
    send_timeout: float = 5.0
    client_queue_size: int = 256
    stats_ttl: float = 5.0
    consumer_name: str = field(default_factory=socket.gethostname)
    consumer_block_ms: int = 5000

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            ingest_token=os.environ.get("INGEST_TOKEN", "").strip(),
            redis_url=_env("REDIS_URL", cls.redis_url),
            database_url=os.environ.get("TIGER_DATABASE_URL", "").strip(),
            domain=_env("DOMAIN", cls.domain),
            ingest_rate_per_sec=float(_env("INGEST_RATE_PER_SEC", "20")),
            ingest_burst=int(_env("INGEST_BURST", "40")),
            ingest_max_batch=int(_env("INGEST_MAX_BATCH", "500")),
        )

    def cors_origins(self) -> list[str]:
        return [
            f"https://{self.domain}",
            f"https://www.{self.domain}",
            "http://localhost:3000",
        ]


# any vercel preview or production deploy
VERCEL_ORIGIN_REGEX = r"https://[a-z0-9-]+\.vercel\.app"
