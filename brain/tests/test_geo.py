from brain.geo import GeoLocator
from brain.networks import categorize

from fakes import FakeAsnReader, FakeCityReader

CITY = FakeCityReader({"203.0.113.42": (52.374123, 4.889765, "NL", "Amsterdam"),
                       "198.51.100.7": (None, None, None, None)})
ASN = FakeAsnReader({"203.0.113.42": (14061, "DIGITALOCEAN-ASN"),
                     "198.51.100.9": (398324, "Censys, Inc."),
                     "198.51.100.10": (3320, "Deutsche Telekom AG")})


def geo(**kw):
    return GeoLocator(CITY, ASN, 30.29, -97.74, **kw)


def test_known_city_rounded(monkeypatch):
    # documentation ranges aren't "global", so patch the check for the fake
    import brain.geo as m
    monkeypatch.setattr(m, "_public", lambda ip: True)
    out = geo().locate("203.0.113.42", "wild")
    assert out == {"lat": 52.37, "lon": 4.89, "country": "NL", "city": "Amsterdam"}


def test_city_without_coords_falls_back(monkeypatch):
    import brain.geo as m
    monkeypatch.setattr(m, "_public", lambda ip: True)
    assert geo().locate("198.51.100.7", "wild")["country"] == "XX"


def test_unknown_ip_falls_back_to_xx():
    out = geo().locate("10.0.0.1", "wild", ip_hash="a" * 64)
    assert out["country"] == "XX" and out["city"] is None
    assert -4 <= out["lat"] <= 4 and -34 <= out["lon"] <= -26
    assert out["lat"] == round(out["lat"], 2)


def test_fallback_is_deterministic_and_spread():
    g = geo()
    a = g.locate("10.0.0.1", "wild", ip_hash="0" * 64)
    b = g.locate("10.0.0.1", "wild", ip_hash="f" * 64)
    assert a == g.locate("10.0.0.2", "wild", ip_hash="0" * 64)
    assert a != b


def test_no_reader_falls_back():
    out = GeoLocator().locate("8.8.8.8", "wild")
    assert out["country"] == "XX"


def test_guest_and_team_use_table():
    for src in ("guest", "team"):
        out = geo().locate("8.8.8.8", src)
        assert out == {"lat": 30.29, "lon": -97.74, "country": "US", "city": "Austin"}


def test_asn_categories(monkeypatch):
    import brain.geo as m
    monkeypatch.setattr(m, "_public", lambda ip: True)
    g = geo()
    assert g.asn("203.0.113.42").category == "cloud"
    assert g.asn("198.51.100.9").category == "scanner"
    assert g.asn("198.51.100.10").category is None
    assert g.asn("198.51.100.10").org == "Deutsche Telekom AG"
    assert g.asn("192.0.2.1").org is None


def test_categorize():
    assert categorize("Amazon.com, Inc.") == "cloud"
    assert categorize("SHODAN") == "scanner"
    assert categorize(None) is None
