"""the llm interface the shell fallback talks to. anthropic is the only provider."""

from __future__ import annotations

import logging
from typing import Protocol

from ..config import Settings

log = logging.getLogger("honeypot.llm")


class LLMError(Exception):
    pass


class LLMTimeout(LLMError):
    pass


class Provider(Protocol):
    async def complete(self, system: str, messages: list[dict], schema: dict) -> str:
        """one request. returns the reply text, which should be json matching schema."""
        ...

    async def close(self) -> None: ...


def make_provider(settings: Settings) -> Provider | None:
    """the configured provider, or None when the fallback should stay off."""
    if settings.llm_provider != "anthropic":
        log.warning("LLM_PROVIDER %r is not supported on the trap, llm fallback is off", settings.llm_provider)
        return None
    if not settings.anthropic_api_key:
        log.warning("ANTHROPIC_API_KEY not set, llm fallback is off")
        return None
    from .anthropic_client import AnthropicProvider

    return AnthropicProvider(settings.anthropic_api_key)
