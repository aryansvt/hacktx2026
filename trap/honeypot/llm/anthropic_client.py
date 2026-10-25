"""anthropic messages client for the shell fallback.

with sender.py, the only module allowed outbound http, and only to API_URL.

one client for the life of the process. its pool keeps connections for
KEEPALIVE seconds (httpx drops them after 5 by default), warm() opens one at
startup, and the fallback calls warm() again now and then so an attacker's
first command doesn't pay for tcp and tls.

plain mode (the default) asks for json in the prompt and lets the fallback
parse it. structured mode sends the json schema, which costs a schema compile
on first use and again after the api's 24 hour cache expires.
"""

from __future__ import annotations

import time

import anthropic
import httpx2

from .provider import LLMError, LLMTimeout, Reply

API_URL = "https://api.anthropic.com"
MODEL = "claude-haiku-5-5"
MAX_TOKENS = 512
TIMEOUT = 6.0
KEEPALIVE = 600.0


class OffTarget(RuntimeError):
    """a request tried to leave for somewhere other than API_URL."""


class AnthropicProvider:
    def __init__(self, api_key: str, model: str = MODEL, structured: bool = False,
                 transport: httpx2.AsyncBaseTransport | None = None):
        url = httpx2.URL(API_URL)
        self._origin = (url.scheme, url.host, url.port)
        limits = httpx2.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=KEEPALIVE)
        self.http = http = anthropic.DefaultAsyncHttpxClient(
            # an explicit transport also stops the sdk from mounting proxies from env vars.
            # the pool lives on the transport, so the keep-alive limits go here
            transport=transport or httpx2.AsyncHTTPTransport(limits=limits),
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
        self.structured = structured

    async def _guard(self, request: httpx2.Request) -> None:
        if (request.url.scheme, request.url.host, request.url.port) != self._origin:
            raise OffTarget("refusing a request that is not for the anthropic api")

    async def warm(self) -> int:
        """GET /v1/models/<model>: no tokens, but it opens and keeps a connection."""
        t0 = time.perf_counter()
        await self.client.models.retrieve(self.model)
        return int((time.perf_counter() - t0) * 1000)

    async def complete(self, system: str, messages: list[dict], schema: dict) -> Reply:
        output_config: dict = {"effort": "low"}
        if self.structured:
            output_config["format"] = {"type": "json_schema", "schema": schema}
        t0 = time.perf_counter()
        try:
            resp = await self.client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=messages,
                # haiku 5.5 only takes the default temperature. thinking off and low effort keep it fast
                thinking={"type": "disabled"},
                output_config=output_config,
            )
        except anthropic.APITimeoutError as e:
            raise LLMTimeout("anthropic timed out") from e
        ms = int((time.perf_counter() - t0) * 1000)
        if resp.stop_reason == "refusal":
            raise LLMError("model declined")
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        if not text:
            raise LLMError(f"empty reply ({resp.stop_reason})")
        usage = resp.usage
        return Reply(text, ms, resp.stop_reason or "", usage.input_tokens, usage.output_tokens)

    async def close(self) -> None:
        await self.client.close()
