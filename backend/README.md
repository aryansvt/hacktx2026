# backend

Runs on core. A FastAPI app that:

- takes raw events from the trap on `POST /ingest` and writes them to Redis stream `raw`
- reads enriched public events from Redis stream `events` (written by brain), stores them in Tiger Data and pushes them to every client on `ws /live`
- serves sessions and stats for the frontend

## Endpoints

| Method | Path | What it does |
| --- | --- | --- |
| POST | `/ingest` | Trap only. JSON array of raw events (`contracts/raw_event.schema.json`), 1 to `INGEST_MAX_BATCH` items. Needs `Authorization: Bearer $INGEST_TOKEN`. Returns `202 {"accepted": n}`. |
| WS | `/live` | Every public event (`contracts/event.schema.json`) as a JSON text message, plus `{"type":"ping"}` every 20 seconds. Ignore pings. |
| GET | `/sessions?limit=50&source=wild` | Newest sessions first, as `session_summary` objects. `limit` 1 to 200, `source` optional. |
| GET | `/sessions/{id}` | `{"session": <summary>, "events": [<event>, ...]}`, events in time order, for replay. 404 if unknown. |
| GET | `/stats` | `contracts/stats.schema.json`. Wild traffic only. Cached for 5 seconds. |
| GET | `/health` | `{"status","redis","db"}`. 503 if either is down. |

Nothing returns raw IPs. Events from brain are checked against the contract before they are stored or sent, and the contract rejects unknown fields like `src_ip`.

### Ingest details

- Rate limited per client IP (`INGEST_RATE_PER_SEC`, `INGEST_BURST`) before the token is checked, so token guessing hits the limit too. Over the limit gets `429` with `Retry-After`.
- Token compared in constant time. If `INGEST_TOKEN` is empty, ingest is off and always returns 401.
- If any event in the batch is invalid, the whole batch is rejected with `422` and the indexes of the bad items. Error messages never echo the input back.
- Each event goes to stream `raw` as one entry with a single field, `data`, holding the event JSON. Brain reads that field.
- The client IP for rate limiting comes from Caddy's `X-Forwarded-For` (uvicorn runs with `--proxy-headers`). Only expose port 8000 to Caddy, never to the internet, or the header can be spoofed.

### Live feed

The consumer reads stream `events` with consumer group `backend`, writes each event to the database, broadcasts it, then acks it. Invalid events are logged and acked so they don't block the stream. If the database write fails, the event is still broadcast but stays pending, and it gets retried on the next start. Writes are idempotent on `event_id`, so a retry never double counts.

Each websocket client has its own queue of 256 messages. Broadcasting never waits on a socket: if a client's queue is full, or one send takes more than 5 seconds, that client is dropped (close code 1013) and the frontend should reconnect.

## Session status

Worked out from events and only ever moves forward:

```
approaching --login_fail--> at_gate --login_success--> inside --session_end--> ended
```

`login_success` from `approaching` goes straight to `inside`. `session_end` from anywhere goes to `ended`. Late, out of order events never move a session back. The session's `attacker` and `geo` come from its newest event, so the session picks up brain's classification once it arrives.

## Database

Migrations are plain SQL files in `migrations/`, run in name order on startup. Each file is idempotent and is recorded in `schema_migrations`.

- `events`: hypertable on `timestamp` with `session_id`, `type`, `source`, `kind`, `threat` and the full event as `data` (JSONB). Indexed on `(session_id, timestamp)`. Retention policy drops chunks older than 7 days.
- `sessions`: one row per session, kept up to date by the consumer. The app deletes rows older than 7 days once an hour.

`/stats` counts only `source = 'wild'`. `per_minute` covers the last 24 hours. It counts wild sessions by the minute they started, grouped by their current attacker kind. Sessions still marked `unknown` are left out until brain classifies them, because brain always sends `session_start` as `unknown`. Only minutes with at least one session are returned.

## Config

All from env vars (see the root `.env.example`):

| Var | Default | |
| --- | --- | --- |
| `TIGER_DATABASE_URL` | required | Postgres connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | |
| `INGEST_TOKEN` | empty (ingest off) | shared with trap |
| `DOMAIN` | `example.com` | CORS allows `https://DOMAIN`, `https://www.DOMAIN`, `https://*.vercel.app`, `http://localhost:3000` |
| `INGEST_RATE_PER_SEC` | `20` | per client IP |
| `INGEST_BURST` | `40` | |
| `INGEST_MAX_BATCH` | `500` | events per request |

## Run it locally

```bash
docker run -d --name hx-redis -p 6379:6379 redis:7-alpine
docker run -d --name hx-tsdb -e POSTGRES_PASSWORD=pw -p 5432:5432 timescale/timescaledb:latest-pg17

python -m venv backend/.venv
backend/.venv/bin/pip install -e contracts/py -e "backend[dev]"

cd backend
INGEST_TOKEN=dev TIGER_DATABASE_URL=postgresql://postgres:pw@localhost:5432/postgres \
  .venv/bin/uvicorn app.main:create_app --factory --reload
```

Fill it with fake traffic (`source = mock`, so it shows on the globe but not in stats):

```bash
python scripts/mock_events.py --rate 2              # forever, about 2 new sessions a second
python scripts/mock_events.py --sessions 20 --pace 0.2
```

## Docker

Build from the repo root, since the image needs `contracts/py`:

```bash
docker build -f backend/Dockerfile -t hacktx-backend .
docker run -p 8000:8000 --env-file .env hacktx-backend
```

## Tests

```bash
cd backend
.venv/bin/python -m pytest
```

The tests use fakeredis and an in-memory store, so they don't need any services. The Postgres tests in `tests/test_pg.py` are skipped unless `TEST_DATABASE_URL` points at a TimescaleDB you don't mind wiping:

```bash
TEST_DATABASE_URL=postgresql://postgres:pw@localhost:5432/postgres .venv/bin/python -m pytest
```
