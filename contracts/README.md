# contracts

These files describe the exact shape of the data moving between our services. If two parts of the system disagree about a field, the schema here wins.

All schemas use JSON Schema draft 2020-12 and reject unknown fields, so a stray `src_ip` or `password` can't sneak through.

## The files

**`raw_event.schema.json`** is what the trap sends to `POST /ingest`. It's the trap's honest notes about what happened: session id, event type, time, whether it was SSH or HTTP, and the attacker's raw IP (`src_ip`). For commands it includes the attacker's exact input line. It has no location or attacker profile yet, because the trap doesn't know those. It never contains a password: login events carry the username and a `success` true/false. The trap only sends six types: `session_start`, `login_fail`, `login_success`, `command`, `tripwire`, `session_end`.

**`event.schema.json`** is the public event the frontend receives over `ws /live`. The brain builds it from a raw event by adding `geo` (rounded to 2 decimals) and an `attacker` profile (bot, human, or agent, reputation, threat level, and so on), and by swapping the raw IP for `ip_hash`. It also has three types the brain creates on its own: `classified`, `dossier`, and `story`. The `detail` object changes with `type`; the schema lists exactly which fields each type has.

**`session_summary.schema.json`** is one session as returned by `GET /sessions` and `GET /sessions/{id}`: when it started and ended, where it came from, who we think it is, how far it got (`approaching`, `at_gate`, `inside`, `ended`), failed logins, command count, and its story if one has been written.

**`attacker_summary.schema.json`** is one attacker as returned by `GET /attackers`: every stored session from one `ip_hash` grouped into a single row, with a visit count, first and last seen times, the newest session's place and profile (`kind`, `confidence`, `reputation`, `family`, `threat`), and up to 50 session ids, newest first. It never has a raw IP, and `ip_hash` can't be null here.

**`stats.schema.json`** is the dashboard numbers from `GET /stats`: totals, how many are active, countries seen, breaches, splits by attacker kind and reputation, and a per-minute timeline. Only `source = wild` traffic counts.

**`examples/`** has sample JSON for every schema. `valid/` files must pass, `invalid/` files must fail. File names start with the schema they belong to, like `event.command.json`.

**`py/`** is a small Python package, `hacktx_contracts`, with pydantic models generated from these schemas. trap, brain, and backend all import it so they share one definition.

## A few field rules

- `timestamp` is always UTC and ends in `Z`, like `2026-10-24T18:03:11.250Z`.
- `country` is an ISO alpha-2 code, or `XX` when we don't know.
- `ip_hash` is a salted sha256 hex string, or null.
- Command `output` is capped at 500 characters.
- `techniques` are MITRE ATT&CK ids like `T1087` or `T1087.001`.
- `source` is `wild` for real attackers, `guest` and `team` for people at our table, `mock` for test data.

## Using the Python models

```bash
pip install -e contracts/py
```

```python
from hacktx_contracts import parse_event, parse_raw_event, AttackerSummary, SessionSummary, Stats

ev = parse_event(json_text)   # returns e.g. CommandEvent, checked against the schema
```

## Changing a schema

1. Edit the `.schema.json` file.
2. Add or update examples in `examples/`.
3. Regenerate the models and run the tests:

```bash
cd contracts/py
pip install -e ".[dev]"
python generate.py
python -m pytest
```

Commit the regenerated files. The tests fail if the models are out of date.
