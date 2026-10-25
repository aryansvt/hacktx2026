# generated from contracts/raw_event.schema.json by contracts/py/generate.py. don't edit.

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, RootModel


class SessionStartDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guest_name: Annotated[str | None, Field(max_length=64)] = None
    client: Annotated[
        str | None, Field(description="ssh client version or http user agent")
    ] = None


class SessionStartRawEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: UUID
    session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    type: Literal["session_start"]
    timestamp: Annotated[
        str,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    protocol: Literal["ssh", "http"]
    src_ip: Annotated[
        IPv4Address | IPv6Address,
        Field(description="raw source ip. stays on core, never sent to the frontend"),
    ]
    detail: SessionStartDetail


class LoginFailDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    username: Annotated[str, Field(max_length=256)]
    success: Literal[False]


class LoginFailRawEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: UUID
    session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    type: Literal["login_fail"]
    timestamp: Annotated[
        str,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    protocol: Literal["ssh", "http"]
    src_ip: Annotated[
        IPv4Address | IPv6Address,
        Field(description="raw source ip. stays on core, never sent to the frontend"),
    ]
    detail: LoginFailDetail


class LoginSuccessDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    username: Annotated[str, Field(max_length=256)]
    success: Literal[True]


class LoginSuccessRawEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: UUID
    session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    type: Literal["login_success"]
    timestamp: Annotated[
        str,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    protocol: Literal["ssh", "http"]
    src_ip: Annotated[
        IPv4Address | IPv6Address,
        Field(description="raw source ip. stays on core, never sent to the frontend"),
    ]
    detail: LoginSuccessDetail


class CommandDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    input: Annotated[
        str, Field(description="the attacker's raw input line. never executed")
    ]
    output: Annotated[str, Field(max_length=500)]
    response_ms: Annotated[int, Field(ge=0)]
    answered_by: Literal["engine", "llm", "cache"]


class CommandRawEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: UUID
    session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    type: Literal["command"]
    timestamp: Annotated[
        str,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    protocol: Literal["ssh", "http"]
    src_ip: Annotated[
        IPv4Address | IPv6Address,
        Field(description="raw source ip. stays on core, never sent to the frontend"),
    ]
    detail: CommandDetail


class TripwireDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    tripwire_id: str
    reasons: list[str]


class TripwireRawEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: UUID
    session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    type: Literal["tripwire"]
    timestamp: Annotated[
        str,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    protocol: Literal["ssh", "http"]
    src_ip: Annotated[
        IPv4Address | IPv6Address,
        Field(description="raw source ip. stays on core, never sent to the frontend"),
    ]
    detail: TripwireDetail


class SessionEndDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    duration_s: Annotated[float, Field(ge=0.0)]
    command_count: Annotated[int, Field(ge=0)]


class SessionEndRawEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: UUID
    session_id: Annotated[
        str,
        Field(
            description="opaque id shared by every event in one session",
            max_length=64,
            min_length=1,
        ),
    ]
    type: Literal["session_end"]
    timestamp: Annotated[
        str,
        Field(
            description="utc, iso 8601, ends in Z, e.g. 2026-10-24T18:03:11.250Z",
            pattern="^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z$",
        ),
    ]
    source: Annotated[
        Literal["wild", "guest", "team", "mock"],
        Field(description="wild = real internet traffic. only wild counts in stats"),
    ]
    protocol: Literal["ssh", "http"]
    src_ip: Annotated[
        IPv4Address | IPv6Address,
        Field(description="raw source ip. stays on core, never sent to the frontend"),
    ]
    detail: SessionEndDetail


class RawEvent(
    RootModel[
        SessionStartRawEvent
        | LoginFailRawEvent
        | LoginSuccessRawEvent
        | CommandRawEvent
        | TripwireRawEvent
        | SessionEndRawEvent
    ]
):
    root: Annotated[
        SessionStartRawEvent
        | LoginFailRawEvent
        | LoginSuccessRawEvent
        | CommandRawEvent
        | TripwireRawEvent
        | SessionEndRawEvent,
        Field(
            description="event trap sends to POST /ingest. no geo or enrichment. passwords are never included.",
            discriminator="type",
            title="RawEvent",
        ),
    ]
