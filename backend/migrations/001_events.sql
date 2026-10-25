-- every public event from brain, as a hypertable on timestamp
create extension if not exists timescaledb;

create table if not exists events (
    event_id    uuid        not null,
    "timestamp" timestamptz not null,
    session_id  text        not null,
    type        text        not null,
    source      text        not null,
    kind        text        not null,
    threat      text        not null,
    data        jsonb       not null
);

select create_hypertable('events', by_range('timestamp'), if_not_exists => true);

-- unique index must include the partition column
create unique index if not exists events_event_id_ts on events (event_id, "timestamp");
create index if not exists events_session_id_ts on events (session_id, "timestamp");

select add_retention_policy('events', drop_after => interval '7 days', if_not_exists => true);
