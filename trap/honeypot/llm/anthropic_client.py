"""anthropic messages client for the shell fallback.

with sender.py, the only module allowed outbound http, and only to API_URL.
"""

from __future__ import annotations

import anthropic
import httpx2

from .provider import LLMError, LLMTimeout

API_URL = "https://api.anthropic.com"
MODEL = "claude-haiku-5-5"
MAX_TOKENS = 800
TIMEOUT = 2.5


class OffTarget(RuntimeError):
    """a request tried to leave for somewhere other than API_URL."""


class AnthropicProvider:
    def __init__(self, api_key: str, model: str = MODEL, transport: httpx2.AsyncBaseTransport | None = None):
        url = httpx2.URL(API_URL)
        self._origin = (url.scheme, url.host, url.port)
        self.http = http = anthropic.DefaultAsyncHttpxClient(
            # an explicit transport also stops the sdk from mounting proxies from env vars
            transport=transport or httpx2.AsyncHTTPTransport(),
            # no redirects and no proxy env vars, so nothing can reroute us
            follow_redirects=False,
            trust_env=False,
            event_hooks={"request": [self._guard]},
        )
        # base_url is pinned so ANTHROPIC_BASE_URL can't point us elsewhere
        self.client = anthropic.AsyncAnthropic(
            api_key=api_key, base_url=API_URL, http_client=http, timeout=TIMEOUT, max_retries=0,
        )
        self.model = model

    async def _guard(self, request: httpx2.Request) -> None:
        if (request.url.scheme, request.url.host, request.url.port) != self._origin:
            raise OffTarget("refusing a request that is not for the anthropic api")

    async def complete(self, system: str, messages: list[dict], schema: dict) -> str:
        try:
            resp = await self.client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=messages,
                # haiku 5.5 only takes the default temperature. thinking off and low effort keep it fast
                thinking={"type": "disabled"},
                output_config={"effort": "low", "format": {"type": "json_schema", "schema": schema}},
            )
        except anthropic.APITimeoutError as e:
            raise LLMTimeout("anthropic timed out") from e
        if resp.stop_reason == "refusal":
            raise LLMError("model declined")
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        if not text:
            raise LLMError(f"empty reply ({resp.stop_reason})")
        return text

    async def close(self) -> None:
        await self.client.close()
