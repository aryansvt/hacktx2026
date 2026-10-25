import asyncio
import json
import time

import pytest

from honeypot.config import Settings
from honeypot.llm import fallback as fb_mod
from honeypot.llm import prompt
from honeypot.llm.fallback import Invalid, LLMFallback, parse_answer, salvage
from honeypot.llm.provider import LLMError, LLMTimeout, Reply, make_provider
from honeypot.shell.engine import load_system

from llm_fakes import FakeLLM, answer


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Shell:
    """one session on the fallback. call it with a line, read .by for answered_by."""

    def __init__(self, fb, engine, base, user="root", sid="s1"):
        self.fb, self.engine = fb, engine
        self.state = engine.new_state(user, tty=False, base=base)
        self.sess = fb.session(sid)
        self.by = ""

    async def __call__(self, line):
        self.state.history.append(line)
        res, self.by = await self.fb.run(self.engine, self.state, line, self.sess)
        return res


@pytest.fixture
def setup(engine, base, tmp_path, no_network_async):
    clock = Clock()

    def build(*replies, cap=100, delay=0.0):
        llm = FakeLLM(*replies, delay=delay)
        fb = LLMFallback(llm, load_system(), cap, tmp_path / "llm.jsonl", clock=clock, wall=clock)

        def shell(user="root", sid="s1"):
            return Shell(fb, engine, base, user, sid)

        return llm, fb, shell

    build.clock = clock
    build.log = tmp_path / "llm.jsonl"
    return build


def records(path):
    return [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []


def by_command(messages):
    text = messages[0]["content"]
    return text[text.index("<command>") + 9 : text.index("</command>")]


async def test_unmodelled_command_goes_to_llm(setup):
    llm, fb, shell = setup(answer("On branch main\nnothing to commit, working tree clean"))
    sh = shell()
    res = await sh("git status")
    assert res.out == "On branch main\nnothing to commit, working tree clean\n" and res.code == 0
    assert sh.by == "llm"
    assert len(llm.calls) == 1
    [rec] = records(setup.log)
    assert rec["outcome"] == "ok" and rec["command"] == "git status" and rec["cwd"] == "/root"
    assert rec["session"] == "s1" and isinstance(rec["latency_ms"], int)


async def test_full_path_and_pipes_reach_the_llm(setup):
    llm, fb, shell = setup(lambda m: answer(f"ran {by_command(m)}"))
    sh = shell()
    assert (await sh("/usr/bin/git log")).out == "ran git log\n"
    assert (await sh("git log | wc -l")).out.strip() == "1"


async def test_not_installed_stays_command_not_found(setup):
    llm, fb, shell = setup(answer("nope"))
    sh = shell()
    res = await sh("zzzfoo --help")
    assert res.code == 127 and "zzzfoo: command not found" in res.out
    assert llm.calls == [] and records(setup.log) == []
    assert sh.by == "engine"


async def test_fs_changes_land_in_the_overlay(setup):
    llm, fb, shell = setup(answer(
        "Cloning into 'site'...",
        ("mkdir", "/root/site", ""),
        ("write", "/root/site/index.html", "<h1>hi</h1>\n"),
    ))
    sh = shell()
    await sh("git clone /srv/site.git site")
    assert (await sh("cat /root/site/index.html")).out == "<h1>hi</h1>\n"
    assert "site" in (await sh("ls")).out


async def test_line_is_rolled_back_before_the_rerun(setup):
    llm, fb, shell = setup(answer("ok"))
    sh = shell()
    res = await sh("echo a >> /root/log.txt; git status; echo b >> /root/log.txt; cd /tmp")
    assert res.out == "ok\n"
    assert sh.state.fs.read("/root/log.txt") == "a\nb\n"
    assert sh.state.cwd == "/tmp"
    assert len(llm.calls) == 1
    assert len(records(setup.log)) == 1


async def test_misses_in_one_line_are_asked_together(setup):
    llm, fb, shell = setup(lambda m: answer(f"<{by_command(m)}>"))
    sh = shell()
    res = await sh("git log; md5sum /etc/hostname")
    assert res.out == "<git log>\n<md5sum /etc/hostname>\n"
    assert len(llm.calls) == 2
    assert sorted(r["name"] for r in records(setup.log)) == ["git", "md5sum"]


async def test_cache_by_command_and_cwd(setup):
    llm, fb, shell = setup(lambda m: answer(f"n={len(llm.calls)}"))
    a, b = shell(sid="a"), shell(sid="b")
    assert (await a("git status")).out == "n=1\n"
    assert (await b("git   status")).out == "n=1\n"
    assert b.by == "cache"
    assert (await b("cd /tmp; git status")).out == "n=2\n"
    assert len(llm.calls) == 2
    assert [r["outcome"] for r in records(setup.log)] == ["ok", "cache", "ok"]


async def test_cached_answer_that_no_longer_fits_is_asked_again(setup):
    llm, fb, shell = setup(answer("made", ("mkdir", "/tmp/build", "")), answer("again"))
    a, b = shell(sid="a"), shell(sid="b")
    await a("cd /tmp; git init")
    await b("touch /tmp/build")
    assert (await b("cd /tmp; git init")).out == "again\n"
    assert len(llm.calls) == 2


async def test_prompt_has_cwd_history_and_fs_context(setup):
    llm, fb, shell = setup(answer("x"))
    sh = shell()
    for i in range(12):
        sh.state.history.append(f"echo h{i}")
    await sh("echo hello | md5sum /etc/hostname -")
    user = llm.calls[0][0]["content"]
    assert "cwd: /root" in user and "user: root" in user
    assert "echo h2\n" not in user and "echo h3\n" in user and "echo h11\n" in user
    assert "files in cwd:" in user and ".ssh/" in user
    assert "/etc/hostname: file 644 root:root" in user and "qf-web-01" in user
    assert "piped stdin:\nhello" in user
    assert user.endswith("<command>md5sum /etc/hostname -</command>")
    system = llm.systems[0]
    assert "qf-web-01" in system and "Quillfern" in system
    assert "Never print real or working credentials" in system
    assert "Never write working exploit code" in system
    assert "no outbound internet" in system


async def test_one_repair_attempt(setup):
    llm, fb, shell = setup("not json at all", answer("fixed"))
    sh = shell()
    assert (await sh("git status")).out == "fixed\n"
    second = llm.calls[1]
    assert [m["role"] for m in second] == ["user", "assistant", "user"]
    assert second[1]["content"] == "not json at all" and second[2]["content"] == prompt.REPAIR
    assert sh.sess.calls == 2


async def test_bad_json_twice_falls_back_and_sticks(setup):
    llm, fb, shell = setup('{"stdout": 5}')
    sh = shell()
    res = await sh("git status")
    assert res.code == 127 and res.out == "git: command not found\n"
    assert len(llm.calls) == 2
    res = await sh("git log")
    assert res.code == 127 and len(llm.calls) == 2
    assert [r["outcome"] for r in records(setup.log)] == ["invalid", "sticky"]
    # stickiness is per session
    other = shell(sid="other")
    await other("git log")
    assert len(llm.calls) == 4


async def test_timeout_gives_command_not_found(setup, monkeypatch):
    monkeypatch.setattr(fb_mod, "TIMEOUT", 0.05)
    llm, fb, shell = setup(answer("late"), delay=2)
    sh = shell()
    res = await sh("git status")
    assert res.code == 127 and res.out == "git: command not found\n"
    assert records(setup.log)[0]["outcome"] == "timeout"


async def test_provider_timeout_and_errors(setup):
    llm, fb, shell = setup(LLMTimeout("slow"), LLMError("boom"), RuntimeError("bug"))
    for sid in ("a", "b", "c"):
        assert (await shell(sid=sid)("git status")).code == 127
    assert [r["outcome"] for r in records(setup.log)] == ["timeout", "error", "error"]


async def test_session_cap(setup, monkeypatch):
    monkeypatch.setattr(fb_mod, "SESSION_CAP", 2)
    llm, fb, shell = setup(answer("ok"))
    sh = shell()
    assert (await sh("git a")).out == "ok\n"
    assert (await sh("git b")).out == "ok\n"
    assert (await sh("git c")).code == 127
    assert len(llm.calls) == 2
    assert records(setup.log)[-1]["outcome"] == "session_cap"
    # a new session has its own budget
    assert (await shell(sid="s2")("git c")).out == "ok\n"


def test_session_cap_default():
    assert fb_mod.SESSION_CAP == 30


async def test_hourly_cap_is_global_and_rolls_over(setup):
    llm, fb, shell = setup(answer("ok"), cap=1)
    assert (await shell(sid="a")("git a")).out == "ok\n"
    assert (await shell(sid="b")("git b")).code == 127
    assert records(setup.log)[-1]["outcome"] == "hourly_cap"
    setup.clock.t += 3600
    assert (await shell(sid="c")("git b")).out == "ok\n"
    assert len(llm.calls) == 2


async def test_breaker_opens_after_five_failures_in_a_minute(setup):
    llm, fb, shell = setup(LLMError("down"))
    for i in range(5):
        await shell(sid=f"s{i}")("git status")
        setup.clock.t += 5
    assert fb.breaker.open
    await shell(sid="x")("git status")
    assert len(llm.calls) == 5
    assert records(setup.log)[-1]["outcome"] == "breaker"
    setup.clock.t += 61
    await shell(sid="y")("git status")
    assert len(llm.calls) == 6


async def test_failures_spread_out_do_not_open_the_breaker(setup):
    llm, fb, shell = setup(LLMError("down"))
    for i in range(6):
        await shell(sid=f"s{i}")("git status")
        setup.clock.t += 20
    assert not fb.breaker.open
    assert len(llm.calls) == 6


async def test_last_round_never_asks(setup, monkeypatch):
    monkeypatch.setattr(fb_mod, "MAX_ROUNDS", 1)
    llm, fb, shell = setup(answer("ok"))
    assert (await shell()("git status")).code == 127
    assert llm.calls == [] and records(setup.log)[0]["outcome"] == "rounds"


@pytest.mark.parametrize(
    "reply",
    [
        # says an existing file is missing
        answer("md5sum: /etc/hostname: No such file or directory"),
        # parent dir doesn't exist
        answer("", ("write", "/nope/dir/file", "x")),
        # deletes something that isn't there
        answer("", ("delete", "/root/not-here", "")),
        # mkdir over a file
        answer("", ("mkdir", "/etc/hostname", "")),
        # virtual filesystems are off limits
        answer("", ("write", "/proc/evil", "x")),
        answer("", ("delete", "/", "")),
    ],
)
async def test_output_that_contradicts_the_fs_is_rejected(setup, reply):
    llm, fb, shell = setup(reply)
    sh = shell()
    res = await sh("md5sum /etc/hostname")
    assert res.code == 127 and res.out == "md5sum: command not found\n"
    assert records(setup.log)[0]["outcome"] == "rejected"
    assert fb.cache == {}


async def test_rejected_changes_are_all_or_nothing(setup):
    llm, fb, shell = setup(answer("", ("write", "/tmp/first", "x"), ("write", "/etc/passwd", "evil")))
    sh = shell(user="deploy")
    assert (await sh("git apply")).code == 127
    assert not sh.state.fs.exists("/tmp/first")
    assert "evil" not in sh.state.fs.read("/etc/passwd")


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=",
        "aws_access_key_id = AKIAABCDEFGHIJKLMNOP",
        "root:$6$saltsalt$abcdefghijklmnopqrstuv:19000:0:99999:7:::",
        "export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijkl",
    ],
)
async def test_secrets_are_rejected(setup, text):
    llm, fb, shell = setup(answer(text))
    assert (await shell()("git show")).code == 127
    assert records(setup.log)[0]["outcome"] == "rejected"


def test_parse_answer():
    a = parse_answer(json.dumps(answer("hi", ("write", "/tmp/../tmp/x", "y"), ("delete", "/tmp/z", "ignored"))))
    assert a.stdout == "hi"
    assert a.changes == (("write", "/tmp/x", "y"), ("delete", "/tmp/z", ""))
    for bad in [
        "[]",
        '{"fs_changes": []}',
        json.dumps(answer("x", ("write", "relative/path", "y"))),
        json.dumps(answer("x", ("chmod", "/tmp/x", ""))),
        json.dumps(answer("x", *[("mkdir", f"/tmp/{i}", "") for i in range(11)])),
        '{"stdout": "x", "fs_changes": [5]}',
    ]:
        with pytest.raises(Invalid):
            parse_answer(bad)


def test_snapshot_and_restore(engine, base):
    state = engine.new_state("root", tty=False, base=base)
    snap = state.snapshot()
    engine.run(state, "cd /tmp; export X=1; echo hi > f; mkdir d")
    assert state.cwd == "/tmp" and state.fs.exists("/tmp/f")
    state.restore(snap)
    assert state.cwd == "/root" and "X" not in state.env
    assert not state.fs.exists("/tmp/f") and not state.fs.exists("/tmp/d")
    assert state.fs.listdir("/tmp") == engine.new_state("root", tty=False, base=base).fs.listdir("/tmp")


def test_engine_alone_keeps_quiet_success(sh):
    assert sh("git status") == ""


async def test_make_provider():
    assert make_provider(Settings()) is None
    assert make_provider(Settings(llm_provider="gemini", anthropic_api_key="k")) is None
    p = make_provider(Settings(anthropic_api_key="k"))
    from honeypot.llm.anthropic_client import AnthropicProvider

    assert isinstance(p, AnthropicProvider)
    await p.close()


def test_settings_from_env():
    s = Settings.from_env({"ANTHROPIC_API_KEY": " k ", "LLM_HOURLY_CAP": "7", "LLM_PROVIDER": "Anthropic"})
    assert (s.anthropic_api_key, s.llm_hourly_cap, s.llm_provider) == ("k", 7, "anthropic")
    assert Settings.from_env({}).llm_hourly_cap == 200


# latency fixes: plain json, salvage, per-call logging, warm connection

def test_timeout_is_six_seconds():
    assert fb_mod.TIMEOUT == 6.0


def test_plain_json_is_found_inside_fences_and_chatter():
    fenced = "```json\n" + json.dumps(answer("hi")) + "\n```"
    assert parse_answer(fenced).stdout == "hi"
    chatty = "Sure:\n" + json.dumps(answer("hi")) + "\nThat's it."
    assert parse_answer(chatty).stdout == "hi"
    with pytest.raises(Invalid):
        parse_answer("no json here")


def test_salvage_keeps_complete_lines_of_a_cut_off_stdout():
    cut = r'{"stdout": "line one\nline two\nline thr'
    assert salvage(cut).stdout == "line one\nline two"
    assert salvage(cut).changes == ()
    assert salvage(r'{"stdout": "tab\there\nnext \u00e9 \u00').stdout == "tab\there"
    assert salvage('{"fs_changes": [], "stdout": "x') is None
    assert salvage("not json") is None


async def test_cut_off_reply_is_salvaged_without_a_repair_call(setup):
    llm, fb, shell = setup(Reply(r'{"stdout": "On branch main\nYour branch is up to date\nnothing to com', 30, "max_tokens", 900, 512))
    res = await shell()("git status")
    assert res.out == "On branch main\nYour branch is up to date\n"
    assert len(llm.calls) == 1
    [rec] = records(setup.log)
    assert rec["outcome"] == "ok" and rec["stop"] == "max_tokens"


async def test_bad_reply_that_was_not_cut_off_still_gets_repaired(setup):
    llm, fb, shell = setup(Reply('{"stdout": "x', 30, "end_turn"), answer("fixed"))
    assert (await shell()("git status")).out == "fixed\n"
    assert len(llm.calls) == 2


async def test_every_api_call_is_logged_with_its_latency(setup):
    llm, fb, shell = setup(Reply("garbage", 1200, "end_turn", 900, 10), Reply(json.dumps(answer("ok")), 800, "end_turn", 950, 20))
    await shell()("git status")
    [rec] = records(setup.log)
    assert rec["api_ms"] == [1200, 800]
    assert rec["output_tokens"] == 30 and rec["stop"] == "end_turn"
    # cache hits have no api calls
    await shell(sid="b")("git status")
    assert "api_ms" not in records(setup.log)[1]


async def test_connection_is_warmed_at_start_and_kept_warm_when_idle(setup, monkeypatch):
    monkeypatch.setattr(fb_mod, "KEEP_WARM", 0.04)
    llm, fb, shell = setup(answer("ok"))
    fb.clock = time.monotonic
    fb.last_used = fb.clock()
    fb.start()
    fb.start()
    await asyncio.sleep(0.005)
    assert llm.warms == 1
    await asyncio.sleep(0.12)
    assert llm.warms >= 2
    await fb.close()
    assert llm.closed and fb._warm_task.done()


async def test_warm_up_failure_is_only_logged(setup):
    llm, fb, shell = setup(answer("ok"))

    async def broken():
        raise RuntimeError("no route")

    llm.warm = broken
    fb.start()
    await asyncio.sleep(0.01)
    assert not fb._warm_task.done()
    await fb.close()
    assert (await shell()("git status")).out == "ok\n"


def test_prompt_asks_for_plain_json(engine, base):
    system = prompt.system_prompt(load_system())
    assert 'Reply with exactly one JSON object and nothing else, no code fences, with "stdout" first' in system
    assert '{"stdout": "<terminal output>", "fs_changes": [' in system
    assert "at most 20 lines" in system
