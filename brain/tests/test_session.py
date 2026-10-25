import fakeredis

from brain.session import Session, SessionStore, fmt_ts, parse_ts


async def test_round_trip_and_ttl():
    r = fakeredis.FakeAsyncRedis()
    store = SessionStore(r, ttl_s=60)
    s = Session("ssh-1", src_ip="203.0.113.1", geo={"lat": 1.0, "lon": 2.0, "country": "NL", "city": None})
    s.add_login(1.0, "root", False)
    s.add_command(2.0, "ls", "x" * 1000)
    await store.save(s)
    got = await store.get("ssh-1")
    assert got == s
    assert len(got.commands[0]["output"]) == 300
    assert 0 < await r.ttl("brain:session:ssh-1") <= 60
    assert await store.get("missing") is None


def test_observe_status_flow():
    s = Session("x")
    s.observe({"type": "session_start", "timestamp": "2026-10-24T18:00:00Z", "detail": {"client": "SSH-2.0-Go"}})
    assert s.status == "approaching" and s.client == "SSH-2.0-Go"
    s.observe({"type": "login_fail", "timestamp": "2026-10-24T18:00:01Z", "detail": {"username": "root", "success": False}})
    assert s.status == "at_gate" and s.login_fails == 1 and not s.logged_in
    s.observe({"type": "login_success", "timestamp": "2026-10-24T18:00:02Z", "detail": {"username": "root", "success": True}})
    assert s.status == "inside" and s.logged_in
    s.observe({"type": "session_end", "timestamp": "2026-10-24T18:00:09Z", "detail": {"duration_s": 9, "command_count": 0}})
    assert s.status == "ended" and s.ended


def test_ts_helpers():
    t = parse_ts("2026-10-24T18:03:11.250Z")
    assert fmt_ts(t) == "2026-10-24T18:03:11.250Z"
