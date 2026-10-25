# scripts/sim

Test and demo tools that connect only to our own honeypot.

- The ssh target is always `TRAP_HOST` from the repo's `.env`. There is no host flag, and `common.connect()` refuses any other host.
- API calls go only to `CORE_URL` from `.env`, over https.
- Every session logs in as `TEAM_SSH_USER`, so the trap tags it `source=team` and it never counts in stats.

## Setup

From the repo root:

```
python3 -m venv .venv
source .venv/bin/activate          # windows: .venv\Scriptsctivate
pip install -r scripts/sim/requirements.txt
```

Every command below assumes the venv is active and you're in the repo root.

`.env` needs `TRAP_HOST`, `TEAM_SSH_USER`, `TEAM_SSH_PASSWORD` and `CORE_URL`. The trap listens on port 22; pass `--port` for anything else.

## sim_bot.py

A fast, regular bot: 4 failed logins in a burst, then a fixed script of system info commands and a simulated download (`wget` from a `.invalid` host, which the trap only pretends to fetch). Sends the `SSH-2.0-Go` client string like most real bots.

```
python scripts/sim/sim_bot.py
python scripts/sim/sim_bot.py -n 5          # five in parallel
python scripts/sim/sim_bot.py --attempts 8  # longer login burst
```

## Tests

```
cd scripts/sim && python -m pytest -q
```
