import copy

import fakeredis
import pytest
from pydantic import ValidationError

from brain.output import build, derived_id, public_detail
from brain.session import Session
from brain.worker import Brain

from fakes import SETTINGS, FakeGeo, event_validator, load_fixture

VALIDATOR = event_validator()


async def run_fixture(name):
    brain = Brain(fakeredis.FakeAsyncRedis(), SETTINGS, FakeGeo())
    out = []
    for raw in load_fixture(name):
        out += await brain.handle(raw)
    return out


@pytest.mark.parametrize("name", ["bot", "human", "agent"])
async def test_every_event_validates_against_schema(name):
    events = await run_fixture(name)
    assert events
    for ev in events:
        errors = list(VALIDATOR.iter_errors(ev))
        assert not errors, (ev["type"], [e.message for e in errors])


@pytest.mark.parametrize("name", ["bot", "human", "agent"])
async def test_no_raw_fields_leak(name):
    raws = load_fixture(name)
    ips = {r["src_ip"] for r in raws}
    for ev in await run_fixture(name):
        text = str(ev)
        assert "src_ip" not in ev and "input" not in ev["detail"] and "success" not in ev["detail"]
        assert "client" not in ev["detail"]
        assert not any(ip in text for ip in ips)
        assert len(ev["attacker"]["ip_hash"]) == 64


async def test_command_events_carry_techniques_and_command():
    events = await run_fixture("bot")
    cmds = [e for e in events if e["type"] == "command"]
    assert cmds[0]["detail"]["command"] == "uname -s -v -n -r -m"
    assert "T1082" in cmds[0]["detail"]["techniques"]
    assert "T1105" in cmds[2]["detail"]["techniques"]


async def test_session_starts_unknown_then_classified():
    events = await run_fixture("agent")
    assert events[0]["type"] == "session_start"
    assert events[0]["attacker"]["kind"] == "unknown"
    assert events[0]["detail"] == {}
    assert events[0]["attacker"]["client"] == "SSH-2.0-paramiko_3.4.0"
    classified = [e for e in events if e["type"] == "classified"]
    assert classified and classified[-1]["attacker"]["kind"] == "agent"
    assert 2 <= len(classified[-1]["detail"]["reasons"]) <= 4


async def test_threat_climbs_and_never_drops():
    order = ["low", "med", "high", "critical"]
    events = await run_fixture("bot")
    levels = [order.index(e["attacker"]["threat"]) for e in events]
    assert levels == sorted(levels)
    assert events[-1]["attacker"]["threat"] == "critical"
    human = await run_fixture("human")
    assert human[-1]["attacker"]["threat"] == "med"


async def test_geo_is_rounded_and_guest_uses_table():
    events = await run_fixture("bot")
    assert events[0]["geo"] == {"lat": 52.37, "lon": 4.89, "country": "NL", "city": "Amsterdam"}
    raws = copy.deepcopy(load_fixture("human"))
    for r in raws:
        r["source"] = "guest"
        r["session_id"] = "ssh-guest1"
    raws[0]["detail"]["guest_name"] = "Ada"
    brain = Brain(fakeredis.FakeAsyncRedis(), SETTINGS, FakeGeo())
    out = await brain.handle(raws[0])
    assert out[0]["geo"] == {"lat": 30.29, "lon": -97.74, "country": "US", "city": "Austin"}
    assert out[0]["detail"] == {"guest_name": "Ada"}
    assert out[0]["source"] == "guest"


async def test_scanner_network_starts_harmless():
    raw = copy.deepcopy(load_fixture("bot")[0])
    raw["src_ip"] = "198.51.100.99"
    out = await Brain(fakeredis.FakeAsyncRedis(), SETTINGS, FakeGeo()).handle(raw)
    assert out[0]["attacker"]["reputation"] == "harmless"
    assert out[0]["attacker"]["family"] == "Censys, Inc."


async def test_attackers_own_ip_masked_in_command():
    raws = copy.deepcopy(load_fixture("bot"))
    raws[6]["detail"]["input"] = "echo 203.0.113.10"
    raws[6]["detail"]["output"] = "203.0.113.10"
    brain = Brain(fakeredis.FakeAsyncRedis(), SETTINGS, FakeGeo())
    out = []
    for r in raws[:7]:
        out += await brain.handle(r)
    cmd = [e for e in out if e["type"] == "command"][-1]
    assert cmd["detail"]["command"] == "echo x.x.x.x"
    assert cmd["detail"]["output"] == "x.x.x.x"


async def test_invalid_raw_rejected():
    raw = copy.deepcopy(load_fixture("bot")[1])
    raw["detail"]["password"] = "hunter2"
    with pytest.raises(ValidationError):
        await Brain(fakeredis.FakeAsyncRedis(), SETTINGS, FakeGeo()).handle(raw)


def test_build_rejects_off_contract_events():
    s = Session("x", ip_hash="a" * 64, geo={"lat": 1.0, "lon": 1.0, "country": "XX", "city": None})
    with pytest.raises(ValidationError):
        build("command", s, "2026-10-24T18:00:00Z", {"command": "ls"}, derived_id("e", "x"))


def test_derived_ids_are_deterministic():
    assert derived_id("abc", "classified") == derived_id("abc", "classified")
    assert derived_id("abc", "classified") != derived_id("abc", "story")


def test_public_detail_drops_unknown_fields():
    s = Session("x")
    raw = {"type": "session_end", "detail": {"duration_s": 1, "command_count": 0, "extra": 1}}
    assert public_detail(raw, s) == {"duration_s": 1, "command_count": 0}
