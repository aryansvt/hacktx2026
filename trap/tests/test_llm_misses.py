import importlib.util
import io
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "llm_misses.py"
spec = importlib.util.spec_from_file_location("llm_misses", SCRIPT)
llm_misses = importlib.util.module_from_spec(spec)
# dataclasses look the module up by name
sys.modules["llm_misses"] = llm_misses
spec.loader.exec_module(llm_misses)


def rec(name, command, outcome, ms):
    return json.dumps({"name": name, "command": command, "outcome": outcome, "latency_ms": ms})


LINES = [
    rec("git", "git status", "ok", 800),
    rec("git", "git status", "cache", 0),
    rec("git", "git log", "timeout", 2500),
    rec("apt", "apt update", "ok", 600),
    "not json",
    "",
    rec("git", "git status", "sticky", 0),
]


def test_groups_by_name_with_outcomes_and_llm_latency():
    rows = llm_misses.summarize(llm_misses.read(LINES))
    assert [(r.key, r.count) for r in rows] == [("git", 4), ("apt", 1)]
    git = rows[0]
    assert git.outcomes == {"ok": 1, "cache": 1, "timeout": 1, "sticky": 1}
    # cache hits and fallbacks don't drag the average down
    assert git.avg_ms == 1650


def test_groups_by_full_command():
    rows = llm_misses.summarize(llm_misses.read(LINES), by="command")
    assert [(r.key, r.count) for r in rows] == [("git status", 3), ("apt update", 1), ("git log", 1)]


def test_render_and_main(tmp_path, capsys):
    out = io.StringIO()
    llm_misses.render(llm_misses.summarize(llm_misses.read(LINES)), 1, out)
    text = out.getvalue()
    assert text.startswith("5 llm-route commands, 2 distinct")
    assert "git" in text and "apt" not in text
    path = tmp_path / "llm.jsonl"
    path.write_text("\n".join(LINES), encoding="utf-8")
    llm_misses.main([str(path), "--by", "command", "--top", "2"])
    shown = capsys.readouterr().out
    assert "git status" in shown and "apt update" in shown and "git log" not in shown
