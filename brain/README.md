# brain

Runs on core. Reads Redis stream `raw`, enriches each event (geo, classification, SerpApi reputation, threat, MITRE technique mapping, dossiers, stories) and writes public events to Redis stream `events`, shaped like `contracts/event.schema.json`.
