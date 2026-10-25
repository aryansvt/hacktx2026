import importlib.util
import sys
from pathlib import Path

from honeypot.llm.provider import LLMTimeout, Reply

from llm_fakes import FakeLLM, answer

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "llm_probe.py"
spec = importlib.util.spec_from_file_location("llm_probe", SCRIPT)
llm_probe = importlib.util.module_from_spec(spec)
sys.modules["llm_probe"] = llm_probe
spec.loader.exec_module(llm_probe)


def test_probe_prints_latency_and_the_parsed_result(capsys):
    llm = FakeLLM(answer("On branch main\nnothing to commit, working tree clean"), ms=812)
    assert llm_probe.main([], provider=llm) == 0
    out = capsys.readouterr().out
    assert "model fake-model, mode plain, timeout 6 s" in out
    assert "warm-up (GET /v1/models): 7 ms" in out
    assert "call 1: 812 ms (ok), stop=end_turn, tokens in=900 out=30" in out
    assert "json: parsed" in out and "    On branch main" in out
    assert llm.warms == 1 and len(llm.calls) == 1 and llm.closed
    # the same prompt the trap builds for git status in /var/www/html
    user = llm.calls[0][0]["content"]
    assert "cwd: /var/www/html" in user and user.endswith("<command>git status</command>")


def test_probe_flags_slow_calls_and_bad_json(capsys):
    llm = FakeLLM(Reply("not json", 7100, "end_turn", 900, 4), Reply('{"stdout": "a\\nb', 300, "max_tokens", 900, 512))
    assert llm_probe.main(["--repeat", "2"], provider=llm) == 1
    out = capsys.readouterr().out
    assert "call 1: 7100 ms" in out and "NOT parseable" in out and "    not json" in out
    assert "call 2: 300 ms (ok), stop=max_tokens" in out and "salvaged from a cut-off reply" in out


def test_probe_reports_failures(capsys):
    assert llm_probe.main(["--repeat", "9"], provider=FakeLLM(LLMTimeout("slow"))) == 2
    out = capsys.readouterr().out
    # repeat is capped at 5
    assert out.count("failed after") == 5


def test_probe_needs_a_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert llm_probe.main([]) == 2
    assert "ANTHROPIC_API_KEY is not set" in capsys.readouterr().err
