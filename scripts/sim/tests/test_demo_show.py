import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import common  # noqa: E402
import demo_show  # noqa: E402


def test_cast_order_and_creatures():
    acts = demo_show.cast("mozi")
    assert [(name, creature) for name, creature, _ in acts] == [
        ("sim_bot", "clay golem"),
        ("sim_bot --family mozi", "stone golem"),
        ("sim_human", "dark mage"),
        ("demo_agent", "fae"),
        ("demo_agent --polite", "purple slime"),
        ("demo_escalation", "dragon"),
    ]


async def test_runs_every_act_even_if_one_fails(monkeypatch):
    calls = []

    async def act(name):
        calls.append(name)
        if name == "b":
            # like demo_agent with no api key
            raise SystemExit("no key")

    monkeypatch.setattr(demo_show, "cast", lambda family: [(n, "x", lambda n=n: act(n)) for n in "abc"])
    results = await demo_show.main(gap=0)
    assert calls == ["a", "b", "c"]
    assert results == [("a", "ok"), ("b", "failed"), ("c", "ok")]


async def test_a_refused_host_stops_the_show(monkeypatch):
    async def refused():
        raise common.NotAllowed("nope")
    monkeypatch.setattr(demo_show, "cast", lambda family: [("a", "x", refused), ("b", "x", refused)])
    with pytest.raises(common.NotAllowed):
        await demo_show.main(gap=0)
