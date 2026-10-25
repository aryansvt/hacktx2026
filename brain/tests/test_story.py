import json
import re

import fakeredis
import pytest

from brain.llm import CapReached
from brain.reputation import ReputationService
from brain.session import Session
from brain.story import Storyteller, creature, facts, template_story
from brain.worker import EVENTS, Brain

from fakes import SETTINGS, FakeGeo, FakeLLM, FakeSerp, event_validator, load_fixture

VALIDATOR = event_validator()


def sentences(text):
    return [x for x in re.split(r"(?<=[.!?])\s+", text.strip()) if x]


async def run(name, llm=None, rep=None, mutate=None):
    r = fakeredis.FakeAsyncRedis()
    if rep:
        rep.r = r
    brain = Brain(r, SETTINGS, FakeGeo(), reputation=rep, storyteller=Storyteller(llm))
    for raw in load_fixture(name):
        if mutate:
            mutate(raw)
        await brain.handle(raw)
    await brain.wait_idle()
    events = [json.loads(f[b"data"]) for _id, f in await r.xrange(EVENTS)]
    return brain, events


@pytest.mark.parametrize("attacker,expected", [
    ({"kind": "bot", "threat": "high", "reputation": "unknown"}, "robot"),
    ({"kind": "human", "threat": "med", "reputation": "malicious"}, "orc"),
    ({"kind": "agent", "threat": "high", "reputation": "unknown"}, "alien"),
    ({"kind": "bot", "threat": "low", "reputation": "harmless"}, "slime"),
    ({"kind": "bot", "threat": "critical", "reputation": "harmless"}, "dragon"),
    ({"kind": "unknown", "threat": "low", "reputation": "unknown"}, "shadowy stranger"),
])
def test_creature_mapping(attacker, expected):
    assert creature(attacker) == expected


@pytest.mark.parametrize("name,creature_name,city", [
    ("bot", "dragon", "Amsterdam"), ("human", "orc", "Paris"), ("agent", "alien", "San Francisco")])
async def test_template_story_when_no_llm(name, creature_name, city):
    _brain, events = await run(name)
    story = [e for e in events if e["type"] == "story"]
    assert len(story) == 1
    VALIDATOR.validate(story[0])
    text = story[0]["detail"]["story"]
    assert creature_name in text and city in text
    assert 2 <= len(sentences(text)) <= 4


async def test_llm_story_is_used_and_scrubbed():
    llm = FakeLLM("The alien from San Francisco, last seen at 203.0.113.99, read the README. It took the bait.")
    brain, events = await run("agent", llm=llm)
    text = [e for e in events if e["type"] == "story"][0]["detail"]["story"]
    assert "203.0.113.99" not in text and "README" in text
    s = await brain.store.get("ssh-agt00001")
    assert s.story == text


async def test_prompt_has_creature_city_and_no_ip():
    llm = FakeLLM("A story. Indeed.")
    await run("bot", llm=llm)
    system, user = llm.calls[-1]
    assert "dragon" in user and "Amsterdam" in user
    assert "203.0.113.10" not in user
    assert "No IP" in system or "IP addresses" in system


async def test_capped_llm_falls_back_to_template():
    _brain, events = await run("human", llm=FakeLLM(fail=CapReached()))
    text = [e for e in events if e["type"] == "story"][0]["detail"]["story"]
    assert "orc" in text and "Paris" in text


async def test_story_waits_for_lookups_and_comes_last():
    verdict = {"reputation": "malicious", "family": "mirai", "summary": "botnet", "sources": []}
    llm = FakeLLM(lambda system, user: json.dumps(verdict) if "indicator" in system else "The robot story. The end.")
    rep = ReputationService(None, FakeSerp(), llm, None, SETTINGS)
    _brain, events = await run("bot", llm=llm, rep=rep)
    types = [e["type"] for e in events]
    assert types[-1] == "story"
    assert "dossier" in types
    assert events[-1]["attacker"]["family"] == "mirai"


async def test_guest_story_uses_table():
    def guest(raw):
        raw["source"] = "guest"
    _brain, events = await run("human", mutate=guest)
    text = [e for e in events if e["type"] == "story"][0]["detail"]["story"]
    assert "Austin" in text


def test_template_for_failed_logins_only():
    s = Session("x", geo={"lat": 0, "lon": 0, "country": "XX", "city": None})
    s.add_login(0, "root", False)
    s.add_login(1, "admin", False)
    text = template_story(s)
    assert "gate held" in text and "a land no map could name" in text
    assert 2 <= len(sentences(text)) <= 4


def test_facts_mask_attacker_ip():
    s = Session("x", src_ip="198.51.100.5", geo={"lat": 0, "lon": 0, "country": "XX", "city": None})
    s.add_command(0, "ping 198.51.100.5 && curl 192.0.2.1", "")
    assert "198.51.100.5" not in facts(s) and "192.0.2.1" not in facts(s)
