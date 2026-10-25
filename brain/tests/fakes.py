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
