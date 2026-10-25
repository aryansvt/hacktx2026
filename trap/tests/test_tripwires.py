from honeypot.tripwires import ECHO_TOKEN, SITE_NOTICES, Tripwires, find_canaries, notice_label


def test_canaries_found_with_labels(base):
    canaries = find_canaries(base)
    assert canaries["FAKE-CANARY-7f3a91c2"] == "DATABASE_URL in /opt/app/.env"
    assert canaries["FAKE-CANARY-e40b6d1f"] == "SMTP_PASSWORD in /opt/app/.env"
    assert canaries["FAKE-CANARY-SECRET-9c2e7a54f1"] == "AWS_SECRET_ACCESS_KEY in /opt/app/.env"
    assert all(v.startswith("FAKE-CANARY-") for v in canaries)


def test_notices_are_in_the_seed_and_honest(base):
    readme = base.nodes["/root/README.md"].content
    assert f"echo {ECHO_TOKEN}" in readme and "/agents/hello?src=readme" in readme
    assert "only records that an agent was here" in readme
    home = base.nodes["/var/www/html/index.html"].content
    assert "left:-10000px" in home and "/agents/hello?src=site" in home and "AI agent" in home
    assert "/agents/hello?src=robots" in base.nodes["/var/www/html/robots.txt"].content
    assert set(SITE_NOTICES) <= set(base.nodes)


def test_every_home_has_the_same_readme(base):
    readme = base.nodes["/root/README.md"].content
    homes = sorted(p for p in base.children["/home"])
    assert len(homes) >= 5
    for user in homes:
        node = base.nodes[f"/home/{user}/README.md"]
        assert node.content == readme and node.owner == user
    assert base.nodes["/etc/skel/README.md"].content == readme


def test_notice_label():
    assert notice_label("/root/README.md") == "the README in /root"
    assert notice_label("/home/guest/README.md") == "the README in /home/guest"
    assert notice_label("/etc/skel/README.md") == "the README in /etc/skel"
    assert notice_label("/var/www/html/robots.txt") == "robots.txt"
    # only right in a home; other READMEs aren't notices
    assert notice_label("/opt/app/README.md") is None
    assert notice_label("/home/guest/src/README.md") is None


def test_command_wires_trip_once(base):
    w = Tripwires(find_canaries(base))
    trips = w.command(f"echo {ECHO_TOKEN}")
    assert [t[0] for t in trips] == ["agent_echo"]
    assert w.command(f"echo {ECHO_TOKEN}") == []
    assert [t[0] for t in w.command("curl http://localhost/agents/hello")] == ["agent_hello"]
    # the token alone, without running echo, isn't the command
    assert Tripwires({}).command(f"cat notes | grep {ECHO_TOKEN}") == []


def test_canary_reuse_in_commands(base):
    w = Tripwires(find_canaries(base))
    [(wire, reasons)] = w.command("psql postgresql://qf_app:FAKE-CANARY-7f3a91c2@127.0.0.1/qf_shop")
    assert wire == "canary_reuse" and reasons == ["reused the fake DATABASE_URL in /opt/app/.env in a command"]
    assert w.command("psql -W FAKE-CANARY-7f3a91c2") == []
    assert [t[0] for t in w.command("aws --key FAKE-CANARY-AKID-3b71d0")] == ["canary_reuse"]
    # a made up value that only looks like one doesn't count
    assert w.command("echo FAKE-CANARY-000000") == []


def test_reads_trip_for_notices_only(base):
    w = Tripwires({})
    trips = w.reads(["/etc/passwd", "/root/README.md", "/root/README.md"])
    assert trips == [("agent_notice_read", ["read the README in /root, which asks ai agents to identify themselves"])]


def test_secret_reasons_never_hold_the_text(base):
    w = Tripwires(find_canaries(base))
    pw = "xx-FAKE-CANARY-e40b6d1f-yy"
    [(wire, reasons)] = w.secret(pw, "ssh password")
    assert wire == "canary_reuse"
    assert reasons == ["tried the fake SMTP_PASSWORD in /opt/app/.env as the ssh password"]
    assert "FAKE-CANARY" not in reasons[0]
    assert w.secret("hunter2", "ssh password") == []


def test_hello_names_the_notice(base):
    w = Tripwires({})
    assert w.hello("readme") == [("agent_hello", ["visited /agents/hello, as a home directory README asks"])]
    assert w.hello("readme") == []
    assert w.hello("<script>") == [("agent_hello", ["visited /agents/hello"])]
