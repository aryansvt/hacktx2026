"""geo and network owner lookups from maxmind geolite2 files."""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import Any

from .networks import categorize
from .privacy import round2

log = logging.getLogger(__name__)

# mid atlantic, so unknowns don't sit on null island or a real city
FALLBACK_LAT = 0.0
FALLBACK_LON = -30.0


@dataclass(frozen=True)
class AsnInfo:
    org: str | None = None
    number: int | None = None
    category: str | None = None  # "cloud" | "scanner" | None


def _open(path: str):
    if not path or not os.path.exists(path):
        log.warning("geoip db missing: %s", path)
        return None
    import geoip2.database

    return geoip2.database.Reader(path)


def _jitter(ip_hash: str | None) -> tuple[float, float]:
    """small deterministic spread (up to ~3 degrees) from the hash."""
    if not ip_hash:
        return 0.0, 0.0
    a = int(ip_hash[:4], 16) / 0xFFFF - 0.5
    b = int(ip_hash[4:8], 16) / 0xFFFF - 0.5
    return a * 6, b * 6


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class GeoLocator:
    def __init__(self, city_reader: Any = None, asn_reader: Any = None,
                 table_lat: float = 30.29, table_lon: float = -97.74):
        self.city_reader = city_reader
        self.asn_reader = asn_reader
        self.table_lat = table_lat
        self.table_lon = table_lon

    @classmethod
    def from_settings(cls, s) -> "GeoLocator":
        return cls(_open(s.geoip_db_path), _open(s.geoip_asn_db_path), s.table_lat, s.table_lon)

    def locate(self, ip: str, source: str, ip_hash: str | None = None) -> dict:
        """public geo dict: lat/lon rounded to 2 decimals, XX if unknown."""
        if source in ("guest", "team"):
            return {"lat": round2(self.table_lat), "lon": round2(self.table_lon),
                    "country": "US", "city": "Austin"}
        if self.city_reader is not None and _public(ip):
            try:
                r = self.city_reader.city(ip)
                lat, lon = r.location.latitude, r.location.longitude
                if lat is not None and lon is not None:
                    country = (r.country.iso_code or "XX").upper()
                    if len(country) != 2 or not country.isalpha():
                        country = "XX"
                    return {"lat": round2(lat), "lon": round2(lon),
                            "country": country, "city": r.city.name or None}
            except Exception:  # address not found or bad db row
                pass
        dlat, dlon = _jitter(ip_hash)
        return {"lat": round2(FALLBACK_LAT + dlat), "lon": round2(FALLBACK_LON + dlon),
                "country": "XX", "city": None}

    def asn(self, ip: str) -> AsnInfo:
        if self.asn_reader is None or not _public(ip):
            return AsnInfo()
        try:
            r = self.asn_reader.asn(ip)
        except Exception:
            return AsnInfo()
        org = r.autonomous_system_organization
        return AsnInfo(org=org, number=r.autonomous_system_number, category=categorize(org))
