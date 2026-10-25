import json
import re

from hacktx_contracts import parse_raw_event

from honeypot.events import JsonlSink, MemorySink, SessionEvents, clean_ip, now_ts


def test_full_session_validates(tmp_path):
    sink = JsonlSink(tmp_path / "spool" / "spool.jsonl")
    ev = SessionEvents(sink, "198.51.100.4")
    ev.session_start("SSH-2.0-Go")
    ev.login_fail("root")
    ev.login_success("root")
    ev.command("uname -a", "Linux qf-web-01\n", 3)
    ev.session_end(4.2, 1)
    ev.resolve("wild")
    lines = (tmp_path / "spool" / "spool.jsonl").read_text().splitlines()
    parsed = [parse_raw_event(line) for line in lines]
    assert [p.type for p in parsed] == ["session_start", "login_fail", "login_success", "command", "session_end"]
    assert {p.session_id for p in parsed} == {ev.session_id}
    assert {p.source for p in parsed} == {"wild"}
    assert all(str(p.src_ip) == "198.51.100.4" for p in parsed)
    assert parsed[3].detail.answered_by == "engine"
    assert len({p.event_id for p in parsed}) == 5


def test_buffered_until_resolved():
    sink = MemorySink()
    ev = SessionEvents(sink, "198.51.100.4")
    ev.session_start(None)
    ev.login_fail("guest")
    assert sink.events == []
    ev.resolve("guest")
    ev.login_success("guest")
    assert [e["source"] for e in sink.events] == ["guest"] * 3
    # a second resolve can't change the source
    ev.resolve("wild")
    ev.command("id", "", 0)
    assert sink.events[-1]["source"] == "guest"


def test_output_and_input_truncated():
    sink = MemorySink()
    ev = SessionEvents(sink, "198.51.100.4")
    ev.resolve("wild")
    ev.command("x" * 10_000, "y" * 2000, 5)
    detail = sink.events[0]["detail"]
    assert len(detail["output"]) == 500
    assert len(detail["input"]) == 4096
    parse_raw_event(sink.events[0])


def test_long_username_truncated():
    sink = MemorySink()
    ev = SessionEvents(sink, "198.51.100.4")
    ev.resolve("wild")
    ev.login_fail("u" * 1000)
    assert len(sink.events[0]["detail"]["username"]) == 256


def test_login_buffer_is_bounded_but_keeps_session_end():
    sink = MemorySink()
    ev = SessionEvents(sink, "198.51.100.4")
    for _ in range(5000):
        ev.login_fail("root")
    ev.session_end(1.0, 0)
    ev.resolve("wild")
    assert len(sink.events) <= 501
    assert sink.events[-1]["type"] == "session_end"


def test_timestamp_format():
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", now_ts())


def test_clean_ip():
    assert clean_ip("::ffff:192.0.2.1") == "192.0.2.1"
    assert clean_ip("fe80::1%eth0") == "fe80::1"
    assert clean_ip("2001:db8::1") == "2001:db8::1"


def test_spool_is_jsonl(tmp_path):
    sink = JsonlSink(tmp_path / "s.jsonl")
    ev = SessionEvents(sink, "192.0.2.1")
    ev.resolve("mock")
    ev.command("echo 'a\nb'", "a\nb\n", 1)
    ev.command("true", "", 0)
    lines = (tmp_path / "s.jsonl").read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["detail"]["input"] == "echo 'a\nb'"
