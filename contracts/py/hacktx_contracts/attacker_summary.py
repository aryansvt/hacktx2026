# generated from contracts/attacker_summary.schema.json by contracts/py/generate.py. don't edit.

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class SessionId(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]


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


class AttackerProfile(BaseModel):
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


class AttackerSummary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ip_hash: Annotated[
        str,
        Field(description="salted sha256 of the source ip", pattern="^[0-9a-f]{64}$"),
    ]
    visits: Annotated[int, Field(description="number of stored sessions", ge=1)]
    first_seen: Annotated[
        str,
        Field(
            description="earliest session start",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    last_seen: Annotated[
        str,
        Field(
            description="latest activity in any session",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    latest_session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    geo: Geo
    attacker: AttackerProfile
    max_threat: Annotated[
        Literal["low", "med", "high", "critical"],
        Field(description="highest threat across every stored session"),
    ]
    session_ids: Annotated[
        list[SessionId],
        Field(
            description="newest first by last activity, capped at 50",
            max_length=50,
            min_length=1,
        ),
    ]
