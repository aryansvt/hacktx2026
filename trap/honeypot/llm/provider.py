"""the llm interface the shell fallback talks to. anthropic is the only provider."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from ..config import Settings

log = logging.getLogger("honeypot.llm")


class LLMError(Exception):
    pass


class LLMTimeout(LLMError):
    pass


@dataclass
class Reply:
    text: str
    # wall time of the one http call, as the trap saw it
    ms: int = 0
    stop: str = "end_turn"
    input_tokens: int = 0
    output_tokens: int = 0


class Provider(Protocol):
    async def complete(self, system: str, messages: list[dict], schema: dict) -> Reply:
        """one request. the reply text should be a json object matching schema."""
        ...

    async def warm(self) -> int:
        """a free request that opens the connection. returns its ms."""
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
