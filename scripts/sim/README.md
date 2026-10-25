# scripts/sim

Test and demo tools that connect only to our own honeypot.

- The ssh target is always `TRAP_HOST` from the repo's `.env`. There is no host flag, and `common.connect()` refuses any other host.
- API calls go only to `CORE_URL` from `.env`, over https.
- Every session logs in as `TEAM_SSH_USER`, so the trap tags it `source=team` and it never counts in stats.

## Setup

From the repo root:

```
python3 -m venv .venv
source .venv/bin/activate          # windows: .venv\Scripts\activate
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

## sim_human.py

A person typing by hand: an OpenSSH client string and a pty, keys sent one at a time with uneven delays, a typo fixed with backspace (`cat /etc/hostanme` -> `hostname`), one typo left in (`sl`), wandering with `cd` and `ls`, reading `.bash_history`, `history`, `docker-compose.yml` and the nginx config. About 2 minutes.

`--short` is 4 plain commands (`ls`, `cat README.md`, `whoami`, `uptime`), the kind of quick look a real visitor takes. It should come out human or unknown, never agent.

```
python scripts/sim/sim_human.py
python scripts/sim/sim_human.py --short
python scripts/sim/sim_human.py --seed 7    # same delays every run
```

The pty's line editor applies backspaces before the trap sees the line, so brain gets the corrected command. The `sl` slip is what shows up as a typo.
