"""privacy helpers: raw ips never leave core."""

from __future__ import annotations

import hashlib
import re

# ipv4 and loose ipv6 (needs at least two colons and a hex group)
_IPV4 = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
_IPV6 = r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4})?\b"
IP_RE = re.compile(f"{_IPV4}|{_IPV6}")


def ip_hash(ip: str, salt: str) -> str:
    """salted sha256 hex of an ip."""
    return hashlib.sha256(f"{salt}{ip}".encode()).hexdigest()


def round2(x: float) -> float:
    return round(float(x), 2)


def scrub_ips(text: str, mask: str = "x.x.x.x") -> str:
    """replace anything that looks like an ip address."""
    return IP_RE.sub(mask, text)


def mask_ip(text: str, ip: str, mask: str = "x.x.x.x") -> str:
    """replace one specific ip (the attacker's own) in text."""
    return text.replace(ip, mask) if ip else text
