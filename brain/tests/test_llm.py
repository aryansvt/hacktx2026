from types import SimpleNamespace as NS

import fakeredis
import pytest

from brain.budget import take
from brain.config import Settings
from brain.llm import AnthropicLLM, CappedLLM, CapReached, LLMError, make_llm

from fakes import FakeLLM


class FakeMessages:
    def __init__(self, resp):
        self.resp = resp
        self.kwargs = None

    async def create(self, **kwargs):
        self.kwargs = kwargs
        return self.resp


def anthropic_with(resp, model="claude-opus-5-5"):
    llm = AnthropicLLM("key", model)
    beta, plain = FakeMessages(resp), FakeMessages(resp)
    llm.client = NS(beta=NS(messages=beta), messages=plain)
    return llm, beta, plain


def reply(text, stop="end_turn"):
    return NS(stop_reason=stop, content=[NS(type="thinking", thinking=""), NS(type="text", text=text)])


async def test_take_counts_against_cap():
    r = fakeredis.FakeAsyncRedis()
    assert await take(r, "x", 2)
    assert await take(r, "x", 2)
    assert not await take(r, "x", 2)
    assert not await take(r, "y", 0)


async def test_capped_llm_raises_when_used_up():
    inner = FakeLLM("hi")
    llm = CappedLLM(inner, fakeredis.FakeAsyncRedis(), cap=1)
    assert await llm.complete("s", "u") == "hi"
    with pytest.raises(CapReached):
        await llm.complete("s", "u")
    assert len(inner.calls) == 1


async def test_anthropic_request_shape_with_schema():
    llm, beta, plain = anthropic_with(reply('{"a": 1}'))
    out = await llm.complete("sys", "user", {"type": "object"})
    assert out == '{"a": 1}'
    k = beta.kwargs
    assert k["model"] == "claude-opus-5-5"
    assert k["fallbacks"] == "default" and k["betas"] == ["server-side-fallback-2026-07-01"]
    assert k["output_config"] == {"effort": "low", "format": {"type": "json_schema", "schema": {"type": "object"}}}
    assert "temperature" not in k and "thinking" not in k
    assert plain.kwargs is None


async def test_anthropic_models_without_fallbacks_use_plain_endpoint():
    llm, beta, plain = anthropic_with(reply("story"), model="claude-haiku-5-5")
    assert await llm.complete("sys", "user") == "story"
    assert beta.kwargs is None and "fallbacks" not in plain.kwargs


async def test_anthropic_refusal_raises():
    llm, _b, _p = anthropic_with(reply("", stop="refusal"))
    with pytest.raises(LLMError):
        await llm.complete("sys", "user")


def test_make_llm_needs_a_key():
    r = fakeredis.FakeAsyncRedis()
    assert make_llm(Settings(), r) is None
    assert isinstance(make_llm(Settings(anthropic_api_key="k"), r), CappedLLM)
    assert make_llm(Settings(llm_provider="gemini"), r) is None
    assert isinstance(make_llm(Settings(llm_provider="gemini", gemini_api_key="k"), r), CappedLLM)


async def _spend(llm, n):
    """how many of n calls went through before the cap."""
    ok = 0
    for _ in range(n):
        try:
            await llm.complete("s", "u")
            ok += 1
        except CapReached:
            pass
    return ok


async def test_wild_traffic_cannot_spend_the_reserve():
    inner = FakeLLM("ok")
    llm = CappedLLM(inner, fakeredis.FakeAsyncRedis(), cap=10, reserved=4)
    # wild calls stop at cap minus the reserve, however many try
    assert await _spend(llm, 50) == 6
    # guest and team still get the held back part, and nothing past the cap
    assert await _spend(llm.ours(), 10) == 4
    assert len(inner.calls) == 10


async def test_our_sessions_use_the_shared_pool_first():
    llm = CappedLLM(FakeLLM("ok"), fakeredis.FakeAsyncRedis(), cap=10, reserved=4)
    assert await _spend(llm.ours(), 8) == 8
    # 6 came from the shared pool, so wild traffic has nothing left
    assert await _spend(llm, 3) == 0
    assert await _spend(llm.ours(), 5) == 2


def test_reserve_never_takes_the_whole_cap():
    r = fakeredis.FakeAsyncRedis()
    assert CappedLLM(FakeLLM(), r, cap=5, reserved=40).reserved == 4
    assert CappedLLM(FakeLLM(), r, cap=0, reserved=40).reserved == 0
    assert make_llm(Settings(anthropic_api_key="k", llm_hourly_cap=200, llm_reserved_hourly=40), r).reserved == 40
