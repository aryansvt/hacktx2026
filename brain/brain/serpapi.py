"""serpapi google search. we only send search strings; attacker urls are never visited."""

from __future__ import annotations

import httpx

URL = "https://serpapi.com/search.json"
MAX_RESULTS = 8


class SerpApi:
    def __init__(self, api_key: str, http: httpx.AsyncClient | None = None):
        self.key = api_key
        self.http = http or httpx.AsyncClient(timeout=20)

    async def search(self, q: str) -> list[dict]:
        r = await self.http.get(URL, params={"engine": "google", "q": q, "num": 10, "api_key": self.key})
        r.raise_for_status()
        rows = r.json().get("organic_results") or []
        return [
            {"title": str(x.get("title", "")), "link": str(x.get("link", "")), "snippet": str(x.get("snippet", ""))}
            for x in rows[:MAX_RESULTS]
        ]

    async def close(self) -> None:
        await self.http.aclose()
