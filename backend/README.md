# backend

Runs on core. FastAPI with `POST /ingest`, `ws /live`, `GET /sessions`, `GET /sessions/{id}` and `GET /stats`. Writes ingested events to Redis stream `raw`, persists enriched events from stream `events` to Tiger Data, and broadcasts them to the frontend.
