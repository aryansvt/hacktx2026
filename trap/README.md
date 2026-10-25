# trap

The honeypot. Runs on its own isolated server. asyncssh SSH server on port 22, FastAPI fake web pages on port 80, and a fake shell (rules engine first, LLM fallback) over a virtual filesystem. It never executes attacker input. It sends raw events to `POST https://api.<domain>/ingest`, shaped like `contracts/raw_event.schema.json`.
