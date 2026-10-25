"""tiger data (timescale postgres) storage. the session state logic lives in sessions.py."""

import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol

import asyncpg

from .sessions import apply_event, parse_ts

log = logging.getLogger(__name__)

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
RETENTION = timedelta(days=7)
ACTIVE_WINDOW = timedelta(minutes=5)
# session ids listed per attacker on /attackers
MAX_SESSION_IDS = 50
# arbitrary constant so only one process migrates at a time
MIGRATION_LOCK = 4_242_026

SESSION_COLUMNS = (
    "session_id",
    "started_at",
    "ended_at",
    "last_seen",
    "source",
    "protocol",
    "status",
    "login_fails",
    "command_count",
    "breached",
    "story",
    "geo",
    "attacker",
)


class Store(Protocol):
    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def ping(self) -> None: ...
    async def persist(self, event: dict[str, Any]) -> bool: ...
    async def list_sessions(self, limit: int, source: str | None) -> list[dict[str, Any]]: ...
    async def list_attackers(self, limit: int, source: str | None) -> list[dict[str, Any]]: ...
    async def get_session(self, session_id: str) -> dict[str, Any] | None: ...
    async def session_events(self, session_id: str) -> list[dict[str, Any]]: ...
    async def stats(self) -> dict[str, Any]: ...
    async def cleanup(self) -> int: ...


async def _init_conn(conn: asyncpg.Connection) -> None:
    for name in ("json", "jsonb"):
        await conn.set_type_codec(name, encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def run_migrations(conn: asyncpg.Connection, folder: Path = MIGRATIONS) -> list[str]:
    """run every .sql file in name order. files are idempotent, applied ones are skipped."""
    await conn.execute("select pg_advisory_lock($1)", MIGRATION_LOCK)
    try:
        await conn.execute(
            "create table if not exists schema_migrations"
            " (name text primary key, applied_at timestamptz not null default now())"
        )
        done = {r["name"] for r in await conn.fetch("select name from schema_migrations")}
        applied = []
        for path in sorted(folder.glob("*.sql")):
            if path.name in done:
                continue
            log.info("applying migration %s", path.name)
            await conn.execute(path.read_text(encoding="utf-8"))
            await conn.execute(
                "insert into schema_migrations (name) values ($1) on conflict do nothing", path.name
            )
            applied.append(path.name)
        return applied
    finally:
        await conn.execute("select pg_advisory_unlock($1)", MIGRATION_LOCK)


_UPSERT_SESSION = f"""
insert into sessions ({", ".join(SESSION_COLUMNS)})
values ({", ".join(f"${i}" for i in range(1, len(SESSION_COLUMNS) + 1))})
on conflict (session_id) do update set
{", ".join(f"{c} = excluded.{c}" for c in SESSION_COLUMNS[1:])}
"""


class PgStore:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        self.pool = await asyncpg.create_pool(
            self.dsn,
            min_size=1,
            max_size=10,
            init=_init_conn,
            server_settings={"timezone": "UTC"},
        )
        async with self.pool.acquire() as conn:
            await run_migrations(conn)

    async def close(self) -> None:
        if self.pool:
            await self.pool.close()

    async def ping(self) -> None:
        await self.pool.fetchval("select 1")

    async def persist(self, event: dict[str, Any]) -> bool:
        """store one public event and fold it into its session. replays are no ops."""
        attacker = event["attacker"]
        async with self.pool.acquire() as conn, conn.transaction():
            inserted = await conn.fetchval(
                """
                insert into events (event_id, "timestamp", session_id, type, source, kind, threat, data)
                values ($1, $2, $3, $4, $5, $6, $7, $8)
                on conflict (event_id, "timestamp") do nothing
                returning true
                """,
                event["event_id"],
                parse_ts(event["timestamp"]),
                event["session_id"],
                event["type"],
                event["source"],
                attacker["kind"],
                attacker["threat"],
                event,
            )
            if not inserted:
                return False
            current = await conn.fetchrow(
                "select * from sessions where session_id = $1 for update", event["session_id"]
            )
            row = apply_event(dict(current) if current else None, event)
            await conn.execute(_UPSERT_SESSION, *(row[c] for c in SESSION_COLUMNS))
            return True

    async def list_sessions(self, limit: int, source: str | None) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            "select * from sessions where ($2::text is null or source = $2)"
            " order by started_at desc limit $1",
            limit,
            source,
        )
        return [dict(r) for r in rows]

    async def list_attackers(self, limit: int, source: str | None) -> list[dict[str, Any]]:
        """one row per ip_hash, profile from its most recent session. attackers.to_row shapes it."""
        rows = await self.pool.fetch(
            """
            with ranked as (
                select session_id, started_at, last_seen, source, geo, attacker,
                       attacker->>'ip_hash' as ip_hash,
                       row_number() over (
                           partition by attacker->>'ip_hash' order by last_seen desc, session_id desc
                       ) as rn
                from sessions
                where attacker->>'ip_hash' is not null and ($2::text is null or source = $2)
            ), grouped as (
                select ip_hash, count(*) as visits, min(started_at) as first_seen,
                       array_agg(session_id order by rn) filter (where rn <= $3) as session_ids
                from ranked
                group by ip_hash
            )
            select g.ip_hash, g.visits, g.first_seen, r.last_seen, r.session_id as latest_session_id,
                   r.source, r.geo, r.attacker, g.session_ids
            from grouped g
            join ranked r on r.ip_hash = g.ip_hash and r.rn = 1
            order by r.last_seen desc, g.ip_hash desc
            limit $1
            """,
            limit,
            source,
            MAX_SESSION_IDS,
        )
        return [dict(r) for r in rows]

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        row = await self.pool.fetchrow("select * from sessions where session_id = $1", session_id)
        return dict(row) if row else None

    async def session_events(self, session_id: str) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            'select data from events where session_id = $1 order by "timestamp", event_id',
            session_id,
        )
        return [r["data"] for r in rows]

    async def stats(self) -> dict[str, Any]:
        """raw wild-only aggregates; stats.build_stats shapes them."""
        async with self.pool.acquire() as conn:
            totals = await conn.fetchrow(
                """
                select
                    count(*) as total,
                    count(*) filter (where status <> 'ended' and last_seen > now() - $1::interval) as active,
                    count(distinct geo->>'country') filter (where geo->>'country' <> 'XX') as countries,
                    count(*) filter (where breached) as breaches
                from sessions
                where source = 'wild'
                """,
                ACTIVE_WINDOW,
            )
            kinds = await conn.fetch(
                "select attacker->>'kind' as k, count(*) as n from sessions"
                " where source = 'wild' group by 1"
            )
            reps = await conn.fetch(
                "select attacker->>'reputation' as k, count(*) as n from sessions"
                " where source = 'wild' group by 1"
            )
            # grouped by the session's current kind, so it updates once brain classifies
            minutes = await conn.fetch(
                """
                select date_trunc('minute', started_at) as t, attacker->>'kind' as k, count(*) as n
                from sessions
                where source = 'wild'
                  and started_at >= now() - interval '24 hours'
                  and attacker->>'kind' in ('bot', 'human', 'agent')
                group by 1, 2
                order by 1
                """
            )
        return {
            "total": totals["total"],
            "active": totals["active"],
            "countries": totals["countries"],
            "breaches": totals["breaches"],
            "by_kind": {r["k"]: r["n"] for r in kinds},
            "by_reputation": {r["k"]: r["n"] for r in reps},
            "per_minute": [(r["t"], r["k"], r["n"]) for r in minutes],
        }

    async def cleanup(self) -> int:
        result = await self.pool.execute(
            "delete from sessions where started_at < now() - $1::interval", RETENTION
        )
        return int(result.split()[-1])
