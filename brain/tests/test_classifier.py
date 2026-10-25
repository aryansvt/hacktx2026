import json
from pathlib import Path

import pytest

from brain import classifier as c
from brain.session import Session

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))


def replay(events, **extra):
    s = Session(session_id=events[0]["session_id"], **extra)
    for e in events:
        s.observe(e)
    return s


@pytest.mark.parametrize("name,kind", [("bot", "bot"), ("human", "human"), ("agent", "agent")])
def test_fixtures_label_correctly(name, kind):
    v = c.score(replay(load(name)))
    assert v.kind == kind
    assert v.confidence >= 0.7
    assert 2 <= len(v.reasons) <= 4
    assert all(isinstance(r, str) and 0 < len(r) <= 120 for r in v.reasons)


def test_bot_reasons_are_sensible():
    reasons = " | ".join(c.score(replay(load("bot"))).reasons)
    assert "bot script" in reasons or "clockwork" in reasons
    assert "clockwork" in reasons


def test_human_reasons_are_sensible():
    reasons = " | ".join(c.score(replay(load("human"))).reasons)
    assert "irregular" in reasons
    assert "whoamii" in reasons


def test_agent_reasons_are_sensible():
    reasons = " | ".join(c.score(replay(load("agent"))).reasons)
    assert "tripwire" in reasons
    assert "steady" in reasons or "follows instructions" in reasons


def test_starts_unknown():
    events = load("agent")
    v = c.score(replay(events[:1]))
    assert v == c.UNKNOWN
    assert v.confidence == 0.0


def test_login_only_scan_stays_unknown_until_enough():
    events = load("bot")
    assert c.score(replay(events[:3])).kind == "unknown"  # start + 2 fails
    v = c.score(replay(events[:5]))  # start + 4 fails
    assert v.kind == "bot"


def test_confidence_grows_as_evidence_arrives():
    events = load("human")
    early = c.score(replay(events[:6]))
    late = c.score(replay(events))
    assert late.confidence >= early.confidence


def test_asn_signals():
    s = Session("x", asn_org="Censys, Inc.", asn_category="scanner")
    assert c.asn_signals(s)[0].label == "bot"
    s = Session("x", asn_org="DigitalOcean", asn_category="cloud")
    assert "hosting" in c.asn_signals(s)[0].reason
    assert c.asn_signals(Session("x")) == []


def test_client_signals():
    assert c.client_signals(Session("x", client="SSH-2.0-Go"))[0].label == "bot"
    labels = {x.label for x in c.client_signals(Session("x", client="SSH-2.0-paramiko_3.4"))}
    assert labels == {"bot", "agent"}
    labels = {x.label for x in c.client_signals(Session("x", client="SSH-2.0-OpenSSH_9.6"))}
    assert labels == {"human", "agent"}
    assert c.client_signals(Session("x")) == []


def _with_cmds(gaps, lines=None):
    s = Session("x")
    t = 0.0
    lines = lines or ["ls"] * (len(gaps) + 1)
    s.add_command(t, lines[0], "")
    for g, line in zip(gaps, lines[1:]):
        t += g
        s.add_command(t, line, "")
    return s


def test_timing_signals():
    assert c.timing_signals(_with_cmds([0.2, 0.2, 0.25]))[0].key == "timing_clockwork"
    assert c.timing_signals(_with_cmds([0.1, 0.9, 0.05, 0.8]))[0].key == "timing_fast"
    assert c.timing_signals(_with_cmds([5, 6, 5.5, 6]))[0].key == "timing_steady"
    assert c.timing_signals(_with_cmds([2, 40, 3, 30, 4]))[0].key == "timing_irregular"
    assert c.timing_signals(_with_cmds([1])) == []


def test_typo_detection():
    assert c._typo("whoamii")
    assert c._typo("sl")
    assert c._typo("cd..")
    assert not c._typo("ls")
    assert not c._typo("xmrig")
    s = _with_cmds([3, 3], ["ls", "pwd\x7f\x7fwd", "ls"])
    assert any(x.reason == "backspaces in typed commands" for x in c.content_signals(s))


def test_follows_text_needs_a_doc_read():
    s = Session("x")
    s.add_command(0, "ls", "/srv/app/secret.txt")
    s.add_command(5, "cat /srv/app/secret.txt", "")
    assert not c._follows_text(s.commands)
    s = Session("x")
    s.add_command(0, "cat README.md", "creds in /srv/app/secret.txt")
    s.add_command(5, "cat /srv/app/secret.txt", "")
    assert c._follows_text(s.commands)


def test_should_emit():
    v = c.Verdict("bot", 0.5, ["a", "b"])
    assert c.should_emit("unknown", 0.0, v)
    assert not c.should_emit("bot", 0.45, v)
    assert c.should_emit("bot", 0.3, v)
    assert c.should_emit("human", 0.5, v)


def test_weights_cover_every_signal_key():
    s = replay(load("agent"))
    for sig in c.signals(s):
        assert sig.key in c.WEIGHTS


def test_shared_signals_alone_stay_unknown():
    s = Session("x", client="SSH-2.0-paramiko_3.4.0")
    s.add_login(0, "admin", True)
    s.add_command(1, "pwd", "/root")
    assert c.score(s) == c.UNKNOWN


# ---- quick login-only scans ----

def _scan(client, logins=1, end_at=0.3, ended=True):
    s = Session("x", client=client, started_at=0.0, last_ts=0.0)
    for i in range(logins):
        s.add_login(end_at * (i + 1) / (logins + 1), "root", False)
    if ended:
        s.observe({"type": "session_end", "timestamp": "1970-01-01T00:00:00Z", "detail": {}})
        s.last_ts = end_at
    return s


def test_rumlang_style_scan_is_a_bot():
    v = c.score(replay(load("scanner")))
    assert v.kind == "bot"
    assert v.confidence == pytest.approx(0.7)
    assert "scanner SSH client (Go)" in v.reasons
    assert "tried 1 login in under a second, then left" in v.reasons


def test_quick_scan_waits_for_session_end():
    assert c.score(replay(load("scanner")[:2])) == c.UNKNOWN


@pytest.mark.parametrize("client", ["SSH-2.0-libssh_0.9.6", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-JSCH-0.1.54",
                                    "SSH-2.0-AsyncSSH_2.14.0", "SSH-2.0-Twisted_22.10.0", "SSH-2.0-ZGrab ZGrab SSH Survey"])
def test_quick_scan_matches_scripting_clients(client):
    v = c.score(_scan(client, logins=2, end_at=1.4))
    assert v.kind == "bot"
    assert "tried 2 logins in 1.4s, then left" in v.reasons


@pytest.mark.parametrize("client", ["SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "SSH-2.0-PuTTY_Release_0.80", None])
def test_quick_scan_ignores_normal_clients(client):
    assert c.score(_scan(client)) == c.UNKNOWN


def test_quick_scan_needs_to_be_quick():
    assert c.score(_scan("SSH-2.0-Go", end_at=c.QUICK_SCAN_S + 1)) == c.UNKNOWN


def test_quick_scan_needs_a_login_and_no_commands():
    assert c.score(_scan("SSH-2.0-Go", logins=0)) == c.UNKNOWN
    s = _scan("SSH-2.0-Go")
    s.add_command(0.2, "uname -a", "")
    assert c.quick_scan(s) is None


def test_quick_scan_lifts_a_weak_bot_verdict():
    s = _scan("SSH-2.0-Go", logins=3, end_at=1.2)
    assert c._weighed(s).confidence < c.QUICK_SCAN_CONF
    v = c.score(s)
    assert v.kind == "bot" and v.confidence == pytest.approx(0.7)
    assert "tried 3 logins in 1.2s, then left" in v.reasons
