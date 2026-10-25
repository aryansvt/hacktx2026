-- one row per session, kept up to date by the events consumer.
-- not a hypertable (pk on session_id), so the app deletes rows older than 7 days.
create table if not exists sessions (
    session_id    text        primary key,
    started_at    timestamptz not null,
    ended_at      timestamptz,
    last_seen     timestamptz not null,
    source        text        not null,
    protocol      text        not null,
    status        text        not null,
    login_fails   integer     not null default 0,
    command_count integer     not null default 0,
    breached      boolean     not null default false,
    story         text,
    geo           jsonb       not null,
    attacker      jsonb       not null
);

create index if not exists sessions_started_at on sessions (started_at desc);
create index if not exists sessions_source_started_at on sessions (source, started_at);
create index if not exists sessions_source_status on sessions (source, status);
