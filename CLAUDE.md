# CLAUDE.md

AI-powered SSH honeypot for HackTX 2026. Attacks show up as fantasy creatures on a live 3D globe.

## Architecture

Two servers plus a frontend on Vercel.

```
attacker ──ssh:22 / http:80──> trap ──HTTPS POST /ingest──> core (Caddy -> backend)
                                                             │
                             backend ──XADD──> redis "raw" ──> brain (enrich)
                                                             │
          redis "events" <──XADD── brain                     │
             │                                               │
             └──> backend ──persist──> Tiger Data (Timescale Postgres)
                          └──broadcast──> wss://api.<domain>/live ──> world (Vercel)
```

- `trap/` runs on its own isolated server ("trap"). Python + asyncssh SSH server on port 22, FastAPI fake web pages on port 80, and a fake shell (rules engine first, LLM fallback) over a virtual filesystem. It NEVER executes attacker input. It sends raw events to core over HTTPS: `POST https://api.<domain>/ingest` with header `Authorization: Bearer $INGEST_TOKEN`.
- `backend/` runs on the "core" server. FastAPI: `POST /ingest` (writes raw events to Redis stream `raw`), `ws /live`, `GET /sessions`, `GET /sessions/{id}`, `GET /stats`. Stores everything in Tiger Data (Timescale Postgres).
- `brain/` runs on core. Reads Redis stream `raw`, enriches events (geo, classification, SerpApi reputation, threat, technique mapping, dossiers, stories) and writes them to Redis stream `events`, which backend persists and broadcasts.
- `world/` is the Next.js frontend, built separately by a teammate on the `world` branch. Don't create or edit anything in `world/`.
- `infra/` holds Docker Compose files, Caddy config, and firewall scripts.
- Caddy on core serves `api.<domain>` with automatic HTTPS so the frontend on Vercel can use `wss://`.
- `contracts/` holds the JSON Schemas every service agrees on, plus the shared pydantic package `hacktx_contracts` (`contracts/py/`).
- `scripts/` holds dev and ops helpers.

## Contracts

- `contracts/raw_event.schema.json`: trap -> `/ingest` -> Redis `raw`.
- `contracts/event.schema.json`: brain -> Redis `events` -> `ws /live`. This is the only event shape the frontend sees.
- `contracts/session_summary.schema.json`: `GET /sessions` and `GET /sessions/{id}`.
- `contracts/stats.schema.json`: `GET /stats`.
- Schemas are the source of truth. After editing one, run `python contracts/py/generate.py` and commit the regenerated models. Never hand-edit `contracts/py/hacktx_contracts/{event,raw_event,session_summary,stats}.py`.
- Python services import models from `hacktx_contracts` (install with `pip install -e contracts/py`).
- Tests: `cd contracts/py && python -m pytest`.

## Rules

### Privacy
- Raw IPs stay on core. Public events use `ip_hash` = salted sha256 of the IP (salt from `IP_HASH_SALT`).
- Geo is rounded to 2 decimals before it leaves core.
- Never log or store passwords. Raw events carry only the username and a success boolean.
- Guest and team sessions use our table location in Austin (`TABLE_LAT`, `TABLE_LON`).

### Safety
- The trap never executes, downloads, or connects anywhere because of attacker input.
- Outbound traffic from trap goes only to `api.<domain>` and the LLM API.

### Data
- Stats count only `source = wild`.

### Code
- Short lowercase code comments.
- Tests for anything with logic.
- Never commit secrets. Config comes from env vars; `.env.example` lists them all.
- No em dashes in copy or docs.
