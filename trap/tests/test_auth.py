import json

from honeypot.auth import Auth, load_pairs
from honeypot.config import DATA, Settings

PAIRS = [("root", "root"), ("admin", "admin")]


def make(**kw) -> Auth:
    return Auth(PAIRS, guest=("guest", "g-pass"), team=("team", "t-pass"), **kw)


def test_default_pairs_are_wild():
    a = make()
    assert a.check("root", "root") == "wild"
    assert a.check("admin", "admin") == "wild"


def test_wrong_or_crossed_pairs_rejected():
    a = make()
    assert a.check("root", "admin") is None
    assert a.check("root", "") is None
    assert a.check("nobody", "root") is None
    assert a.check("ROOT", "root") is None


def test_guest_and_team_logins():
    a = make()
    assert a.check("guest", "g-pass") == "guest"
    assert a.check("team", "t-pass") == "team"
    assert a.check("guest", "t-pass") is None
    assert a.check("team", "g-pass") is None


def test_demo_logins_disabled_without_password():
    a = Auth(PAIRS, guest=("guest", ""), team=("team", ""))
    assert a.check("guest", "") is None
    assert a.check("team", "") is None


def test_team_ip_wins():
    a = make(team_ips=frozenset({"192.0.2.7"}))
    assert a.source_for("192.0.2.7", "wild") == "team"
    assert a.source_for("192.0.2.7", None) == "team"
    assert a.source_for("198.51.100.1", "guest") == "guest"
    assert a.source_for("198.51.100.1", None) == "wild"


def test_non_ascii_input_does_not_crash():
    assert make().check("röot", "päss\udc80") is None


def test_load_from_settings(tmp_path):
    path = tmp_path / "logins.json"
    path.write_text(json.dumps({"allow": [["pi", "raspberry"]]}))
    env = {
        "TRAP_LOGINS_PATH": str(path),
        "GUEST_SSH_USER": "guest",
        "GUEST_SSH_PASSWORD": "hello",
        "TEAM_IPS": " 192.0.2.7 , ,192.0.2.8",
    }
    a = Auth.load(Settings.from_env(env))
    assert a.check("pi", "raspberry") == "wild"
    assert a.check("root", "root") is None
    assert a.check("guest", "hello") == "guest"
    assert a.team_ips == {"192.0.2.7", "192.0.2.8"}


def test_shipped_logins_file():
    pairs = load_pairs(DATA / "logins.json")
    assert ("root", "root") in pairs and len(pairs) >= 20
