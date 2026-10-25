"""settings read from env vars. every var is listed in .env.example."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    redis_url: str = "redis://localhost:6379/0"
    database_url: str = ""
    ip_hash_salt: str = ""
    geoip_db_path: str = "./data/GeoLite2-City.mmdb"
    geoip_asn_db_path: str = "./data/GeoLite2-ASN.mmdb"
    table_lat: float = 30.29
    table_lon: float = -97.74
    llm_provider: str = "anthropic"
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    anthropic_model: str = "claude-opus-5-5"
    gemini_model: str = "gemini-2.5-flash"
    serpapi_key: str = ""
    serpapi_hourly_cap: int = 50
    llm_hourly_cap: int = 200
    # held back from wild traffic so guest and team sessions always get a story
    llm_reserved_hourly: int = 40
    consumer: str = "brain-1"
    session_ttl_s: int = 86400

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ.get
        return cls(
            redis_url=e("REDIS_URL", cls.redis_url),
            database_url=e("TIGER_DATABASE_URL", ""),
            ip_hash_salt=e("IP_HASH_SALT", ""),
            geoip_db_path=e("GEOIP_DB_PATH", cls.geoip_db_path),
            geoip_asn_db_path=e("GEOIP_ASN_DB_PATH", cls.geoip_asn_db_path),
            table_lat=_float("TABLE_LAT", cls.table_lat),
            table_lon=_float("TABLE_LON", cls.table_lon),
            llm_provider=e("LLM_PROVIDER", cls.llm_provider).lower(),
            anthropic_api_key=e("ANTHROPIC_API_KEY", ""),
            gemini_api_key=e("GEMINI_API_KEY", ""),
            anthropic_model=e("BRAIN_ANTHROPIC_MODEL", cls.anthropic_model),
            gemini_model=e("BRAIN_GEMINI_MODEL", cls.gemini_model),
            serpapi_key=e("SERPAPI_KEY", ""),
            serpapi_hourly_cap=_int("SERPAPI_HOURLY_CAP", cls.serpapi_hourly_cap),
            llm_hourly_cap=_int("LLM_HOURLY_CAP", cls.llm_hourly_cap),
            llm_reserved_hourly=_int("LLM_RESERVED_HOURLY", cls.llm_reserved_hourly),
            consumer=e("BRAIN_CONSUMER", cls.consumer),
            session_ttl_s=_int("BRAIN_SESSION_TTL_S", cls.session_ttl_s),
        )
