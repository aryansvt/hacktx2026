# generated from contracts/event.schema.json by contracts/py/generate.py. don't edit.

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, RootModel


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


class DossierSource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    title: str
    url: AnyUrl


class SessionStartDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guest_name: Annotated[str | None, Field(max_length=64)] = None


class SessionStartEvent(BaseModel):
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
    geo: Geo
    attacker: Attacker
    detail: SessionStartDetail


class LoginFailDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    username: Annotated[str, Field(max_length=256)]


class LoginFailEvent(BaseModel):
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
    geo: Geo
    attacker: Attacker
    detail: LoginFailDetail


class LoginSuccessDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    username: Annotated[str, Field(max_length=256)]


class LoginSuccessEvent(BaseModel):
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
    geo: Geo
    attacker: Attacker
    detail: LoginSuccessDetail


class Technique(RootModel[str]):
    root: Annotated[str, Field(pattern="^T\\d{4}(\\.\\d{3})?$")]


class CommandDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    command: Annotated[str, Field(description="the command as shown publicly")]
    output: Annotated[str, Field(max_length=500)]
    response_ms: Annotated[int, Field(ge=0)]
    answered_by: Literal["engine", "llm", "cache"]
    techniques: Annotated[
        list[Technique], Field(description="mitre att&ck technique ids")
    ]


class CommandEvent(BaseModel):
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
    geo: Geo
    attacker: Attacker
    detail: CommandDetail


class TripwireDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    tripwire_id: str
    reasons: list[str]


class TripwireEvent(BaseModel):
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
    geo: Geo
    attacker: Attacker
    detail: TripwireDetail


class ClassifiedDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    reasons: list[str]


class ClassifiedEvent(BaseModel):
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
    type: Literal["classified"]
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
    geo: Geo
    attacker: Attacker
    detail: ClassifiedDetail


class DossierDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    summary: str
    sources: list[DossierSource]


class DossierEvent(BaseModel):
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
    type: Literal["dossier"]
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
    geo: Geo
    attacker: Attacker
    detail: DossierDetail


class StoryDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    story: str


class StoryEvent(BaseModel):
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
    type: Literal["story"]
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
    geo: Geo
    attacker: Attacker
    detail: StoryDetail


class SessionEndDetail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    duration_s: Annotated[float, Field(ge=0.0)]
    command_count: Annotated[int, Field(ge=0)]


class SessionEndEvent(BaseModel):
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
    geo: Geo
    attacker: Attacker
    detail: SessionEndDetail


class Event(
    RootModel[
        SessionStartEvent
        | LoginFailEvent
        | LoginSuccessEvent
        | CommandEvent
        | TripwireEvent
        | ClassifiedEvent
        | DossierEvent
        | StoryEvent
        | SessionEndEvent
    ]
):
    root: Annotated[
        SessionStartEvent
        | LoginFailEvent
        | LoginSuccessEvent
        | CommandEvent
        | TripwireEvent
        | ClassifiedEvent
        | DossierEvent
        | StoryEvent
        | SessionEndEvent,
        Field(
            description="public event sent to the frontend over ws /live. never contains raw ips or passwords.",
            discriminator="type",
            title="Event",
        ),
    ]
