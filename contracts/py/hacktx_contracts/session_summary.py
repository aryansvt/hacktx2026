# generated from contracts/session_summary.schema.json by contracts/py/generate.py. don't edit.

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class Geo(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lat: Annotated[float, Field(description="rounded to 2 decimals", ge=-90.0, le=90.0)]
    lon: Annotated[
        float, Field(description="rounded to 2 decimals", ge=-180.0, le=180.0)
    ]
    country: Annotated[
        str,
        Field(description="iso 3166-1 alpha-2, XX if unknown", pattern="^[A-Z]{2}$"),
    ]
    city: str | None


class Attacker(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["bot", "human", "agent", "unknown"]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    reputation: Literal["harmless", "unknown", "malicious"]
    family: Annotated[
        str | None, Field(description="known botnet or tool family, if any")
    ]
    threat: Literal["low", "med", "high", "critical"]
    client: Annotated[
        str | None, Field(description="ssh client version or http user agent")
    ]
    ip_hash: Annotated[
        str | None,
        Field(description="salted sha256 of the source ip", pattern="^[0-9a-f]{64}$"),
    ]


class SessionSummary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    started_at: Annotated[
        str,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    ended_at: Annotated[
        str | None,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    geo: Geo
    attacker: Attacker
    status: Literal["approaching", "at_gate", "inside", "ended"]
    login_fails: Annotated[int, Field(ge=0)]
    command_count: Annotated[int, Field(ge=0)]
    story: str | None
