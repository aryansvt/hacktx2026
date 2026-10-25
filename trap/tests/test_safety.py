"""static guard: nothing in honeypot/ can run, spawn or connect on the host."""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "honeypot"

BANNED_MODULES = {
    "subprocess", "pty", "socket", "ctypes", "importlib", "multiprocessing",
    "http.client", "urllib.request", "requests", "httpx", "httpx2", "aiohttp", "anthropic",
}
BANNED_CALLS = {"eval", "exec", "compile", "__import__"}
BANNED_OS = {"system", "popen", "fork", "forkpty", "execl", "execle", "execlp", "execlpe", "execv",
             "execve", "execvp", "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
             "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp", "startfile"}

# relative path -> modules it may import. these are the only two that reach out
ALLOW: dict[str, set[str]] = {
    "sender.py": {"httpx"},
    "llm/anthropic_client.py": {"anthropic", "httpx2"},
}


def _banned_module(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in BANNED_MODULES)


def violations(source: str, rel: str = "<snippet>") -> list[str]:
    allowed = ALLOW.get(rel, set())
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _banned_module(a.name) and a.name not in allowed:
                    found.append(f"{rel}:{node.lineno} import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level == 0 and _banned_module(mod) and mod not in allowed:
                found.append(f"{rel}:{node.lineno} from {mod} import")
            if mod == "os":
                for a in node.names:
                    if a.name in BANNED_OS:
                        found.append(f"{rel}:{node.lineno} from os import {a.name}")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in BANNED_CALLS:
                found.append(f"{rel}:{node.lineno} call {fn.id}()")
            if isinstance(fn, ast.Attribute) and fn.attr in BANNED_OS and isinstance(fn.value, ast.Name) and fn.value.id == "os":
                found.append(f"{rel}:{node.lineno} call os.{fn.attr}()")
            if isinstance(fn, ast.Attribute) and fn.attr in BANNED_CALLS and isinstance(fn.value, ast.Name) and fn.value.id == "builtins":
                found.append(f"{rel}:{node.lineno} call builtins.{fn.attr}()")
    return found


def test_honeypot_never_executes_or_connects():
    files = sorted(ROOT.rglob("*.py"))
    assert len(files) > 5
    found = []
    for path in files:
        found += violations(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
    assert found == []


@pytest.mark.parametrize(
    "snippet",
    [
        "import subprocess",
        "import socket",
        "from http.client import HTTPConnection",
        "import urllib.request",
        "from os import system",
        "import os\nos.system('id')",
        "import os\nos.execvp('sh', ['sh'])",
        "eval('1')",
        "exec('x = 1')",
        "__import__('subprocess')",
        "import builtins\nbuiltins.exec('1')",
    ],
)
def test_scanner_catches(snippet):
    assert violations(snippet)


def test_sender_and_llm_client_are_the_only_http_modules():
    assert ALLOW == {"sender.py": {"httpx"}, "llm/anthropic_client.py": {"anthropic", "httpx2"}}
    assert violations("import httpx", "shell/engine.py")
    assert violations("import anthropic", "llm/fallback.py")
    assert violations("from anthropic import AsyncAnthropic", "shell/engine.py")
    assert violations("import httpx2", "sender.py")
    assert violations("import anthropic", "sender.py")
    assert violations("import httpx", "llm/anthropic_client.py")
    assert violations("import httpx", "sender.py") == []
    assert violations("import anthropic\nimport httpx2", "llm/anthropic_client.py") == []


def test_sender_has_no_hardcoded_urls():
    # the only place it can post to is CORE_URL from the env
    tree = ast.parse((ROOT / "sender.py").read_text(encoding="utf-8"))
    urls = [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and "://" in n.value
    ]
    assert urls == []


def test_llm_client_only_knows_the_anthropic_api():
    tree = ast.parse((ROOT / "llm" / "anthropic_client.py").read_text(encoding="utf-8"))
    urls = [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and "://" in n.value
    ]
    assert urls == ["https://api.anthropic.com"]


def test_scanner_allows_plain_code():
    assert violations("import os, json, asyncio\nos.path.join('a', 'b')\nos.chmod('x', 0o600)") == []
