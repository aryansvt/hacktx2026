import json
import re

import fakeredis
import pytest

from brain.llm import CapReached
from brain.reputation import ReputationService
from brain.session import Session
from brain.story import Storyteller, creature, facts, label, tag, template_story
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
    ({"kind": "bot", "threat": "high", "reputation": "unknown"}, "clay golem"),
    ({"kind": "bot", "threat": "high", "reputation": "malicious"}, "stone golem"),
    ({"kind": "human", "threat": "med", "reputation": "unknown"}, "dark mage"),
    ({"kind": "human", "threat": "med", "reputation": "malicious"}, "evil witch"),
    ({"kind": "agent", "threat": "high", "reputation": "unknown"}, "fae"),
    ({"kind": "agent", "threat": "high", "reputation": "malicious"}, "cursed fae"),
    ({"kind": "bot", "threat": "low", "reputation": "harmless"}, "slime"),
    ({"kind": "bot", "threat": "critical", "reputation": "harmless"}, "dragon"),
    ({"kind": "human", "threat": "critical", "reputation": "malicious"}, "dragon"),
    ({"kind": "unknown", "threat": "low", "reputation": "unknown"}, "shadowy stranger"),
    ({"kind": "unknown", "threat": "low", "reputation": "malicious"}, "shadowy stranger"),
])
def test_creature_mapping(attacker, expected):
    assert creature(attacker) == expected


@pytest.mark.parametrize("kind,expected", [
    ("bot", "bot"), ("human", "human"), ("agent", "AI agent"), ("unknown", "unknown")])
def test_label_mapping(kind, expected):
    assert label({"kind": kind}) == expected


@pytest.mark.parametrize("text,who,what,expected", [
    ("A clay golem lumbered in. The clay golem left.", "clay golem", "bot",
     "A clay golem (bot) lumbered in. The clay golem left."),
    ("The Fae danced in from Oslo.", "fae", "AI agent", "The Fae (AI agent) danced in from Oslo."),
    ("A dark mage (human) came by.", "dark mage", "human", "A dark mage (human) came by."),
    ("Something came by.", "slime", "bot", "Something came by."),
    ("The faery fae came.", "fae", "AI agent", "The faery fae (AI agent) came."),
])
def test_tag_marks_first_mention(text, who, what, expected):
    assert tag(text, who, what) == expected


@pytest.mark.parametrize("name,creature_name,city", [
    ("bot", "dragon (bot)", "Amsterdam"), ("human", "dark mage (human)", "Paris"),
    ("agent", "fae (AI agent)", "San Francisco")])
async def test_template_story_when_no_llm(name, creature_name, city):
    _brain, events = await run(name)
    story = [e for e in events if e["type"] == "story"]
    assert len(story) == 1
    VALIDATOR.validate(story[0])
    text = story[0]["detail"]["story"]
    assert creature_name in text and city in text
    assert text.count("(") == 1
    assert 2 <= len(sentences(text)) <= 4


async def test_llm_story_is_used_and_scrubbed():
    llm = FakeLLM("The fae from San Francisco, last seen at 203.0.113.99, read the README. It took the bait.")
    brain, events = await run("agent", llm=llm)
    text = [e for e in events if e["type"] == "story"][0]["detail"]["story"]
    assert "203.0.113.99" not in text and "README" in text
    assert text.startswith("The fae (AI agent) from San Francisco")
    s = await brain.store.get("ssh-agt00001")
    assert s.story == text


async def test_llm_story_keeps_its_own_label():
    llm = FakeLLM("A fae (AI agent) drifted in from San Francisco. The fae read the README.")
    _brain, events = await run("agent", llm=llm)
    text = [e for e in events if e["type"] == "story"][0]["detail"]["story"]
    assert text == "A fae (AI agent) drifted in from San Francisco. The fae read the README."


async def test_prompt_has_creature_label_city_and_no_ip():
    llm = FakeLLM("A story. Indeed.")
    await run("bot", llm=llm)
    system, user = llm.calls[-1]
    assert "dragon" in user and "(bot)" in user and "Amsterdam" in user
    assert "203.0.113.10" not in user
    assert "No IP" in system or "IP addresses" in system
    assert "parentheses" in system


async def test_capped_llm_falls_back_to_template():
    _brain, events = await run("human", llm=FakeLLM(fail=CapReached()))
    text = [e for e in events if e["type"] == "story"][0]["detail"]["story"]
    assert "dark mage (human)" in text and "Paris" in text


async def test_story_waits_for_lookups_and_comes_last():
    verdict = {"reputation": "malicious", "family": "mirai", "summary": "botnet", "sources": []}
    llm = FakeLLM(lambda system, user: json.dumps(verdict) if "indicator" in system else "The golem story. The end.")
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
    assert "shadowy stranger (unknown)" in text
    assert 2 <= len(sentences(text)) <= 4


def test_facts_mask_attacker_ip():
    s = Session("x", src_ip="198.51.100.5", geo={"lat": 0, "lon": 0, "country": "XX", "city": None})
    s.add_command(0, "ping 198.51.100.5 && curl 192.0.2.1", "")
    assert "198.51.100.5" not in facts(s) and "192.0.2.1" not in facts(s)
