"""test doubles for geoip readers, serpapi, the llm and the tiger cache."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS


class NotFound(Exception):
    pass


class FakeCityReader:
    def __init__(self, rows: dict):
        self.rows = rows

    def city(self, ip):
        if ip not in self.rows:
            raise NotFound(ip)
        lat, lon, country, city = self.rows[ip]
        return NS(location=NS(latitude=lat, longitude=lon),
                  country=NS(iso_code=country), city=NS(name=city))


class FakeAsnReader:
    def __init__(self, rows: dict):
        self.rows = rows

    def asn(self, ip):
        if ip not in self.rows:
            raise NotFound(ip)
        num, org = self.rows[ip]
        return NS(autonomous_system_number=num, autonomous_system_organization=org)


class FakeSerp:
    def __init__(self, results=None):
        self.queries: list[str] = []
        self.results = results if results is not None else [
            {"title": "AbuseIPDB report", "link": "https://www.abuseipdb.com/check/x",
             "snippet": "reported 120 times for ssh brute force, mirai"},
            {"title": "GreyNoise", "link": "https://viz.greynoise.io/ip/x",
             "snippet": "malicious scanner"},
        ]

    async def search(self, q: str):
        self.queries.append(q)
        return list(self.results)


class FakeLLM:
    def __init__(self, reply=None, fail: Exception | None = None):
        self.calls: list[tuple[str, str]] = []
        self.reply = reply
        self.fail = fail

    async def complete(self, system: str, user: str, json_mode: bool = False) -> str:
        self.calls.append((system, user))
        if self.fail:
            raise self.fail
        if callable(self.reply):
            return self.reply(system, user)
        if self.reply is not None:
            return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        return "A story."


class MemoryRepCache:
    """same interface as cache_db.PgReputationCache."""

    def __init__(self):
        self.rows: dict[str, tuple[dict, datetime]] = {}
        self.gets = 0

    async def start(self):
        pass

    async def get(self, key: str):
        self.gets += 1
        row = self.rows.get(key)
        if not row:
            return None
        result, created = row
        if datetime.now(timezone.utc) - created > timedelta(days=7):
            return None
        return result, created

    async def put(self, key: str, kind: str, result: dict):
        self.rows[key] = (result, datetime.now(timezone.utc))

    async def close(self):
        pass


# ---- brain wiring for tests ----

from brain.config import Settings  # noqa: E402
from brain.geo import GeoLocator  # noqa: E402

SETTINGS = Settings(ip_hash_salt="test-salt", consumer="test-1", session_ttl_s=3600,
                    serpapi_hourly_cap=50, llm_hourly_cap=200)


class FakeGeo(GeoLocator):
    """fixture ips are documentation ranges, so skip the public-ip check."""

    CITIES = {
        "203.0.113.10": (52.374123, 4.889765, "NL", "Amsterdam"),
        "198.51.100.20": (48.8566, 2.3522, "FR", "Paris"),
        "192.0.2.30": (37.7749, -122.4194, "US", "San Francisco"),
    }
    ASNS = {
        "203.0.113.10": (14061, "DIGITALOCEAN-ASN"),
        "198.51.100.20": (3215, "Orange S.A."),
        "192.0.2.30": (16509, "AMAZON-02"),
        "198.51.100.99": (398324, "Censys, Inc."),
    }

    def __init__(self):
        super().__init__(FakeCityReader(self.CITIES), FakeAsnReader(self.ASNS), 30.29, -97.74)

    def locate(self, ip, source, ip_hash=None):
        import brain.geo as m
        orig, m._public = m._public, (lambda _ip: True)
        try:
            return super().locate(ip, source, ip_hash)
        finally:
            m._public = orig

    def asn(self, ip):
        import brain.geo as m
        orig, m._public = m._public, (lambda _ip: True)
        try:
            return super().asn(ip)
        finally:
            m._public = orig


def load_fixture(name):
    from pathlib import Path
    return json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))


def event_validator():
    from pathlib import Path

    from jsonschema import Draft202012Validator
    schema_path = Path(__file__).resolve().parents[2] / "contracts" / "event.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
