import json

import fakeredis
from hacktx_contracts import parse_event

from brain import backfill as b
from brain.worker import EVENTS

from fakes import event_validator

VALIDATOR = event_validator()


def ev(i, typ, ts, sid="ssh-rumlang1", client="SSH-2.0-Go", detail=None):
    return {
        "event_id": f"00000000-0000-4000-8000-{i:012d}",
        "session_id": sid,
        "type": typ,
        "timestamp": ts,
        "source": "wild",
        "protocol": "ssh",
        "geo": {"lat": 47.45, "lon": 8.53, "country": "CH", "city": "Rümlang"},
        "attacker": {"kind": "unknown", "confidence": 0.0, "reputation": "malicious", "family": None,
                     "threat": "low", "client": client, "ip_hash": "c" * 64},
        "detail": detail if detail is not None else {},
    }


def rumlang(sid="ssh-rumlang1", client="SSH-2.0-Go"):
    """stored public events: a 0.3s login-only scan, with a story written seconds later."""
    return [
        ev(1, "session_start", "2026-10-24T19:12:07.000Z", sid, client),
        ev(2, "login_fail", "2026-10-24T19:12:07.150Z", sid, client, {"username": "root"}),
        ev(3, "session_end", "2026-10-24T19:12:07.300Z", sid, client, {"duration_s": 0.3, "command_count": 0}),
        ev(4, "story", "2026-10-24T19:12:19.000Z", sid, client, {"story": "A shadowy stranger knocked once."}),
    ]


def test_session_rebuilt_from_public_events():
    s = b.session_from_events(rumlang())
    assert s.client == "SSH-2.0-Go" and s.ended
    assert [x["username"] for x in s.logins] == ["root"]
    # brain-made events don't stretch the session, or quick scans would look slow
    assert round(s.last_ts - s.started_at, 3) == 0.3


def test_rumlang_session_gets_a_classified_event():
    events = rumlang()
    out = b.classified_event(events)
    VALIDATOR.validate(out)
    parse_event(out)
    assert out["type"] == "classified" and out["session_id"] == "ssh-rumlang1"
    assert out["attacker"]["kind"] == "bot" and out["attacker"]["confidence"] == 0.7
    assert "scanner SSH client (Go)" in out["detail"]["reasons"]
    # latest stored timestamp, so the backend takes the new profile without moving last_seen
    assert out["timestamp"] == events[-1]["timestamp"]
    # everything else carries over from the latest event
    assert out["attacker"]["reputation"] == "malicious" and out["attacker"]["ip_hash"] == "c" * 64
    assert out["geo"] == events[-1]["geo"]
    # same id on every run, so a rerun can't double count
    assert b.classified_event(rumlang())["event_id"] == out["event_id"]


def test_still_unknown_gives_no_event():
    assert b.classified_event(rumlang(client="SSH-2.0-OpenSSH_9.6")) is None
    assert b.classified_event([]) is None


def test_commands_are_rebuilt():
    events = [ev(1, "session_start", "2026-10-24T19:00:00.000Z", client="SSH-2.0-OpenSSH_9.6")]
    for i, (t, line) in enumerate([("01.000", "whoamii"), ("04.000", "ls"), ("40.000", "cd /tmp"),
                                   ("43.000", "ls"), ("90.000", "cd .."), ("95.000", "clear")]):
        sec = float(t)
        ts = f"2026-10-24T19:{int(sec // 60):02d}:{sec % 60:06.3f}Z"
        events.append(ev(i + 2, "command", ts, client="SSH-2.0-OpenSSH_9.6",
                         detail={"command": line, "output": "", "response_ms": 5, "answered_by": "engine",
                                 "techniques": []}))
    events.append(ev(99, "session_end", "2026-10-24T19:01:40.000Z", client="SSH-2.0-OpenSSH_9.6",
                     detail={"duration_s": 100.0, "command_count": 6}))
    s = b.session_from_events(events)
    assert [c["input"] for c in s.commands][:2] == ["whoamii", "ls"]
    out = b.classified_event(events)
    assert out is not None and out["attacker"]["kind"] == "human"


async def sessions(*groups):
    for g in groups:
        yield g if isinstance(g, tuple) else (g, 0)


async def test_dry_run_only_counts():
    r = fakeredis.FakeAsyncRedis()
    counts = await b.backfill(sessions(rumlang("a"), rumlang("b", "SSH-2.0-OpenSSH_9.6")), r, dry_run=True)
    assert counts == {"checked": 2, "classified": 1, "still_unknown": 1, "by_kind": {"bot": 1}}
    assert await r.xlen(EVENTS) == 0


async def test_backfill_writes_classified_events():
    r = fakeredis.FakeAsyncRedis()
    counts = await b.backfill(sessions(rumlang("a"), rumlang("b"), rumlang("c", "SSH-2.0-PuTTY_0.80")), r)
    assert counts["classified"] == 2
    written = [json.loads(f[b"data"]) for _id, f in await r.xrange(EVENTS)]
    assert [e["session_id"] for e in written] == ["a", "b"]
    for e in written:
        VALIDATOR.validate(e)


def test_busy_ip_classifies_an_openssh_session():
    events = rumlang(client="SSH-2.0-OpenSSH_9.6")
    assert b.classified_event(events, recent_sessions=9) is None
    out = b.classified_event(events, recent_sessions=11)
    VALIDATOR.validate(out)
    assert out["attacker"]["kind"] == "bot" and out["attacker"]["confidence"] == 0.75
    assert out["detail"]["reasons"][0] == "connected 11 times in the last hour"


async def test_backfill_passes_visit_counts_through():
    r = fakeredis.FakeAsyncRedis()
    openssh = "SSH-2.0-OpenSSH_9.6"
    counts = await b.backfill(sessions((rumlang("a", openssh), 10), (rumlang("b", openssh), 3)), r)
    assert counts == {"checked": 2, "classified": 1, "still_unknown": 1, "by_kind": {"bot": 1}}


class FakePool:
    def __init__(self, sessions, events):
        self.sessions, self.events, self.queries = sessions, events, []

    async def fetch(self, sql, *args):
        self.queries.append((sql, args))
        if args and isinstance(args[0], str):
            return [{"data": e} for e in self.events[args[0]]]
        return self.sessions


async def test_stored_sessions_yield_events_with_visit_counts():
    pool = FakePool([{"session_id": "a", "recent_sessions": 12}, {"session_id": "b", "recent_sessions": 0}],
                    {"a": rumlang("a"), "b": rumlang("b")})
    got = [(events[0]["session_id"], n) async for events, n in b.stored_sessions(pool)]
    assert got == [("a", 12), ("b", 0)]
    sql, args = pool.queries[0]
    # same one hour window and wild-only rule as the live tracker
    assert args == (3600,) and "source = 'wild'" in sql
