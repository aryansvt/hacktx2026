import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import common  # noqa: E402


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(common, "ENV", {
        "TRAP_HOST": "203.0.113.5",
        "CORE_URL": "https://api.example.com",
        "TEAM_SSH_USER": "team",
        "TEAM_SSH_PASSWORD": "x",
    })


def test_only_trap_host_is_allowed():
    assert common.check_host("203.0.113.5") == "203.0.113.5"
    assert common.check_host(" 203.0.113.5 ") == "203.0.113.5"
    for bad in ("8.8.8.8", "localhost", "203.0.113.50", "api.example.com", ""):
        with pytest.raises(common.NotAllowed):
            common.check_host(bad)


def test_empty_or_wildcard_trap_host_refuses(monkeypatch):
    monkeypatch.setitem(common.ENV, "TRAP_HOST", "")
    with pytest.raises(SystemExit):
        common.check_host("")
    monkeypatch.setitem(common.ENV, "TRAP_HOST", "0.0.0.0")
    with pytest.raises(SystemExit):
        common.check_host("0.0.0.0")


async def test_connect_never_leaves_the_allowlist(monkeypatch):
    seen = []

    async def fake_connect(host, port, **kw):
        seen.append((host, port, kw["username"]))
        return "conn"

    monkeypatch.setattr(common.asyncssh, "connect", fake_connect)
    assert await common.connect(2222) == "conn"
    assert seen == [("203.0.113.5", 2222, "team")]


def test_api_urls_stay_on_core_url():
    assert common.check_api_url("https://api.example.com/sessions")
    for bad in ("http://api.example.com/sessions", "https://evil.example/sessions",
                "https://api.example.com.evil.example/x"):
        with pytest.raises(common.NotAllowed):
            common.check_api_url(bad)


def test_core_url_must_be_https(monkeypatch):
    monkeypatch.setitem(common.ENV, "CORE_URL", "http://api.example.com")
    with pytest.raises(SystemExit):
        common.api_base()


@pytest.mark.parametrize("text", ["team@qf-web-01:~$ ", "root@qf-web-01:/opt/app# ", "out\nteam@qf-web-01:/tmp$ "])
def test_prompt_detected(text):
    assert common.PROMPT_RE.search(text)


@pytest.mark.parametrize("text", ["team@qf-web-01:~$ ls", "price is 5$ ", "[sudo] password for team: "])
def test_not_a_prompt(text):
    assert not common.PROMPT_RE.search(text)


def test_latest_reasons_takes_the_last_classified():
    events = [{"type": "classified", "detail": {"reasons": ["a"]}}, {"type": "command"},
              {"type": "classified", "detail": {"reasons": ["b", "c"]}}]
    assert common.latest_reasons(events) == ["b", "c"]
    assert common.latest_reasons([]) == []
