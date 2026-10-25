# generated from contracts/stats.schema.json by contracts/py/generate.py. don't edit.

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ByKind(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bot: Annotated[int, Field(ge=0)]
    human: Annotated[int, Field(ge=0)]
    agent: Annotated[int, Field(ge=0)]
    unknown: Annotated[int, Field(ge=0)]


class ByReputation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    harmless: Annotated[int, Field(ge=0)]
    unknown: Annotated[int, Field(ge=0)]
    malicious: Annotated[int, Field(ge=0)]


class MinuteBucket(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    t: Annotated[
        str,
        Field(
            description="start of the minute, utc",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    bot: Annotated[int, Field(ge=0)]
    human: Annotated[int, Field(ge=0)]
    agent: Annotated[int, Field(ge=0)]


class Stats(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    total_sessions: Annotated[int, Field(ge=0)]
    active_now: Annotated[int, Field(ge=0)]
    countries: Annotated[int, Field(description="distinct countries seen", ge=0)]
    breaches: Annotated[
        int, Field(description="sessions that logged in successfully", ge=0)
    ]
    by_kind: ByKind
    by_reputation: ByReputation
    per_minute: list[MinuteBucket]
