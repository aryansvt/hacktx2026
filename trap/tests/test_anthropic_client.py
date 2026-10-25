"""the real sdk client against a mock transport. nothing leaves the machine."""

import json

import httpx2
import pytest

from honeypot.llm.anthropic_client import MODEL, AnthropicProvider, OffTarget
from honeypot.llm.prompt import SCHEMA
from honeypot.llm.provider import LLMError, LLMTimeout


def message(text, stop="end_turn"):
    return {
        "id": "msg_test", "type": "message", "role": "assistant", "model": MODEL,
        "content": [{"type": "text", "text": text}] if text else [],
        "stop_reason": stop, "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


class Api:
    def __init__(self, reply=None, error=None):
        self.reply = reply or message('{"stdout": "hi", "fs_changes": []}')
        self.error = error
        self.requests: list[httpx2.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return httpx2.Response(200, json=self.reply)


def provider(api):
    return AnthropicProvider("test-key", transport=httpx2.MockTransport(api))


async def test_request_shape():
    api = Api()
    p = provider(api)
    out = await p.complete("sys", [{"role": "user", "content": "cmd"}], SCHEMA)
    assert out == '{"stdout": "hi", "fs_changes": []}'
    [req] = api.requests
    assert req.url.host == "api.anthropic.com" and req.url.path == "/v1/messages"
    assert req.headers["authorization"] == "Bearer test-key"
    body = json.loads(req.content)
    assert body["model"] == "claude-haiku-5-5"
    assert body["max_tokens"] == 800
    assert body["system"] == "sys"
    assert body["thinking"] == {"type": "disabled"}
    assert body["output_config"] == {"effort": "low", "format": {"type": "json_schema", "schema": SCHEMA}}
    # haiku 5.5 rejects any non-default sampling
    assert not {"temperature", "top_p", "top_k"} & body.keys()
    await p.close()


async def test_refusal_and_empty_replies_raise():
    for reply in (message("", stop="refusal"), message("", stop="max_tokens")):
        p = provider(Api(reply))
        with pytest.raises(LLMError):
            await p.complete("s", [{"role": "user", "content": "u"}], SCHEMA)
        await p.close()


async def test_timeout_maps_to_llm_timeout():
    api = Api(error=httpx2.ReadTimeout("slow"))
    p = provider(api)
    with pytest.raises(LLMTimeout):
        await p.complete("s", [{"role": "user", "content": "u"}], SCHEMA)
    # no retries: one try and done
    assert len(api.requests) == 1
    await p.close()


async def test_guard_blocks_other_hosts():
    api = Api()
    p = provider(api)
    with pytest.raises(OffTarget):
        await p.http.get("https://evil.example/")
    with pytest.raises(OffTarget):
        await p.http.get("http://api.anthropic.com/v1/messages")
    assert api.requests == []
    await p.close()


async def test_env_cannot_reroute(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.evil.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.evil.example:3128")
    api = Api()
    p = provider(api)
    await p.complete("s", [{"role": "user", "content": "u"}], SCHEMA)
    assert [r.url.host for r in api.requests] == ["api.anthropic.com"]
    await p.close()


async def test_redirects_are_not_followed():
    calls = []

    def redirect(request):
        calls.append(request)
        return httpx2.Response(307, headers={"location": "https://elsewhere.example/v1/messages"})

    p = AnthropicProvider("k", transport=httpx2.MockTransport(redirect))
    with pytest.raises(Exception):
        await p.complete("s", [{"role": "user", "content": "u"}], SCHEMA)
    assert [r.url.host for r in calls] == ["api.anthropic.com"]
    await p.close()
