from brain.privacy import ip_hash, mask_ip, round2, scrub_ips


def test_ip_hash_is_salted_sha256():
    h = ip_hash("203.0.113.42", "salt")
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
    assert h != ip_hash("203.0.113.42", "other")
    assert h == ip_hash("203.0.113.42", "salt")


def test_round2():
    assert round2(52.37412) == 52.37
    assert round2(-97.7449) == -97.74


def test_scrub_ips_v4_and_v6():
    out = scrub_ips("from 203.0.113.42 and 2001:db8::1 to fe80:0:0:0:1:2:3:4")
    assert "203.0.113.42" not in out
    assert "2001:db8::1" not in out
    assert "fe80:0:0:0:1:2:3:4" not in out


def test_scrub_ips_leaves_times_and_versions():
    assert scrub_ips("at 18:03 run v1.2.3") == "at 18:03 run v1.2.3"


def test_mask_ip():
    assert mask_ip("ping 1.2.3.4", "1.2.3.4") == "ping x.x.x.x"
    assert mask_ip("ping", "") == "ping"
