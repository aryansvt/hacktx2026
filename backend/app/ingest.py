"""POST /ingest: raw trap events -> redis stream "raw"."""

import hmac
import json
import math

from fastapi import APIRouter, HTTPException, Request
from hacktx_contracts import parse_raw_event
from pydantic import ValidationError

router = APIRouter()

RAW_STREAM = "raw"
RAW_MAXLEN = 100_000


def _authorized(header: str | None, token: str) -> bool:
    if not token or not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer ") :].encode(), token.encode())


@router.post("/ingest", status_code=202)
async def ingest(request: Request) -> dict:
    state = request.app.state
    settings = state.settings

    ip = request.client.host if request.client else "unknown"
    ok, retry_after = state.limiter.allow(ip)
    if not ok:
        raise HTTPException(429, "rate limited", headers={"Retry-After": str(math.ceil(retry_after))})

    if not _authorized(request.headers.get("authorization"), settings.ingest_token):
        raise HTTPException(401, "unauthorized", headers={"WWW-Authenticate": "Bearer"})

    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > settings.ingest_max_bytes:
        raise HTTPException(413, "body too large")
    body = await request.body()
    if len(body) > settings.ingest_max_bytes:
        raise HTTPException(413, "body too large")

    try:
        items = json.loads(body)
    except ValueError:
        raise HTTPException(422, "body is not json")
    if not isinstance(items, list) or not items:
        raise HTTPException(422, "body must be a non-empty json array of raw events")
    if len(items) > settings.ingest_max_batch:
        raise HTTPException(413, f"at most {settings.ingest_max_batch} events per request")

    errors = []
    for i, item in enumerate(items):
        try:
            parse_raw_event(item)
        except ValidationError as e:
            # never echo input back: it could hold attacker data
            errors.append(
                {"index": i, "errors": [{"loc": list(err["loc"]), "msg": err["msg"]} for err in e.errors()]}
            )
    if errors:
        raise HTTPException(422, {"message": "invalid raw events", "invalid": errors})

    pipe = state.redis.pipeline(transaction=False)
    for item in items:
        pipe.xadd(RAW_STREAM, {"data": json.dumps(item)}, maxlen=RAW_MAXLEN, approximate=True)
    await pipe.execute()
    return {"accepted": len(items)}
