"""read api. everything here comes from public events, so no raw ips exist to leak."""

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket
from fastapi.responses import JSONResponse
from hacktx_contracts import SessionSummary, Stats

from .sessions import to_summary
from .stats import build_stats

log = logging.getLogger(__name__)

router = APIRouter()

Source = Literal["wild", "guest", "team", "mock"]


@router.get("/sessions", response_model=list[SessionSummary])
async def list_sessions(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    source: Source | None = None,
) -> list[dict]:
    rows = await request.app.state.store.list_sessions(limit, source)
    return [to_summary(r) for r in rows]


@router.get("/sessions/{session_id}")
async def get_session(request: Request, session_id: str) -> dict:
    store = request.app.state.store
    row = await store.get_session(session_id)
    if row is None:
        raise HTTPException(404, "session not found")
    # validate the summary; events were already checked against the contract on the way in
    summary = SessionSummary.model_validate(to_summary(row)).model_dump(mode="json")
    return {"session": summary, "events": await store.session_events(session_id)}


@router.get("/stats", response_model=Stats)
async def stats(request: Request) -> dict:
    state = request.app.state

    async def load() -> dict:
        return build_stats(await state.store.stats())

    return await state.stats_cache.get(load)


@router.get("/health")
async def health(request: Request):
    state = request.app.state
    checks = {}
    for name, ping in (("redis", state.redis.ping), ("db", state.store.ping)):
        try:
            await ping()
            checks[name] = "ok"
        except Exception as e:
            log.warning("health check %s failed: %s", name, e)
            checks[name] = "down"
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse({"status": "ok" if ok else "degraded", **checks}, status_code=200 if ok else 503)


@router.websocket("/live")
async def live(ws: WebSocket) -> None:
    await ws.app.state.hub.serve(ws)
