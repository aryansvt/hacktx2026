"""llm clients for dossiers and stories, behind an hourly cap."""

from __future__ import annotations

import json
import logging

import httpx

from .budget import take

log = logging.getLogger(__name__)


class CapReached(Exception):
    pass


class LLMError(Exception):
    pass


# models that accept server-side refusal fallbacks
_FALLBACK_PREFIXES = ("claude-opus-5", "claude-fable-5", "claude-sonnet-5-5")


class AnthropicLLM:
    def __init__(self, api_key: str, model: str):
        from anthropic import AsyncAnthropic

        self.client = AsyncAnthropic(api_key=api_key, timeout=60, max_retries=2)
        self.model = model

    async def complete(self, system: str, user: str, schema: dict | None = None) -> str:
        output_config: dict = {"effort": "low"}
        if schema:
            output_config["format"] = {"type": "json_schema", "schema": schema}
        kwargs: dict = dict(
            model=self.model,
            max_tokens=4000,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config=output_config,
        )
        if self.model.startswith(_FALLBACK_PREFIXES):
            # honeypot logs can trip safety classifiers; let the api reroute instead of failing
            resp = await self.client.beta.messages.create(
                betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
        else:
            resp = await self.client.messages.create(**kwargs)
        if resp.stop_reason == "refusal":
            raise LLMError("model declined")
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        if not text:
            raise LLMError(f"empty reply ({resp.stop_reason})")
        return text


class GeminiLLM:
    URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self, api_key: str, model: str, http: httpx.AsyncClient | None = None):
        self.key = api_key
        self.model = model
        self.http = http or httpx.AsyncClient(timeout=60)

    async def complete(self, system: str, user: str, schema: dict | None = None) -> str:
        body: dict = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
        }
        if schema:
            body["generationConfig"] = {"responseMimeType": "application/json"}
        r = await self.http.post(self.URL.format(model=self.model), json=body,
                                 headers={"x-goog-api-key": self.key})
        r.raise_for_status()
        try:
            parts = r.json()["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            raise LLMError(f"bad gemini reply: {e}") from e
        text = "".join(p.get("text", "") for p in parts).strip()
        if not text:
            raise LLMError("empty reply")
        return text


class CappedLLM:
    """counts every call against LLM_HOURLY_CAP before making it. part of the cap is held back for our own sessions."""

    def __init__(self, inner, redis, cap: int, reserved: int = 0):
        self.inner = inner
        self.r = redis
        self.cap = cap
        # never hold back the whole cap
        self.reserved = max(0, min(reserved, cap - 1))

    async def complete(self, system: str, user: str, schema: dict | None = None) -> str:
        if not await take(self.r, "llm", self.cap - self.reserved):
            raise CapReached("llm hourly cap reached")
        return await self.inner.complete(system, user, schema)

    def ours(self) -> "ReservedLLM":
        """the same llm for guest and team sessions, which may also spend the held back part."""
        return ReservedLLM(self)


class ReservedLLM:
    """shared pool first, then the reserve. both pools together never pass LLM_HOURLY_CAP."""

    def __init__(self, capped: CappedLLM):
        self.c = capped

    async def complete(self, system: str, user: str, schema: dict | None = None) -> str:
        c = self.c
        if not await take(c.r, "llm", c.cap - c.reserved) and not await take(c.r, "llm_reserved", c.reserved):
            raise CapReached("llm hourly cap reached, reserve too")
        return await c.inner.complete(system, user, schema)


def make_llm(settings, redis):
    """the configured llm behind the hourly cap, or None if there are no keys."""
    if settings.llm_provider == "gemini" and settings.gemini_api_key:
        inner = GeminiLLM(settings.gemini_api_key, settings.gemini_model)
    elif settings.llm_provider == "anthropic" and settings.anthropic_api_key:
        inner = AnthropicLLM(settings.anthropic_api_key, settings.anthropic_model)
    else:
        log.warning("no llm key for provider %r; dossiers and stories use templates", settings.llm_provider)
        return None
    return CappedLLM(inner, redis, settings.llm_hourly_cap, settings.llm_reserved_hourly)
