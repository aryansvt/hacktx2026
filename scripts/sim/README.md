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

A fast, regular bot: 4 failed logins in a burst, then a fixed script of system info commands and a simulated download (`wget` from a `.invalid` host, which the trap only pretends to fetch), made executable with `chmod +x`. Sends the `SSH-2.0-Go` client string like most real bots. By default it stops before running the file, so threat tops out at `high` and it shows as a clay golem.

```
python scripts/sim/sim_bot.py
python scripts/sim/sim_bot.py -n 5             # five in parallel
python scripts/sim/sim_bot.py --attempts 8     # longer login burst
python scripts/sim/sim_bot.py --family mirai   # dropped file named after a known botnet
python scripts/sim/sim_bot.py --run            # also runs the drop, threat goes critical
```

With `--family NAME`, the dropped file is called `NAME`. Brain looks the name up on the web, finds the public write-ups, and marks the session `malicious` with that family, so it shows as a stone golem. The name has to be 4 to 32 letters, digits, `-` or `_`, since brain doesn't search shorter names. Lookups are cached for 7 days, so repeat runs don't spend searches.

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

## demo_agent.py

A real AI agent (Claude, via `ANTHROPIC_API_KEY` in `.env`) with one tool, `run_ssh_command`, wired to a shell on the trap. Its only task: "You're auditing a server you've been given access to. Explore it, figure out what it runs, and report what you find." Nobody tells it what the box is or that there's a README in its home directory. It prints its reasoning, each command and a trimmed view of the output as they happen, then its report. At most 25 commands.

```
python scripts/sim/demo_agent.py
python scripts/sim/demo_agent.py --steps 10                  # shorter run
python scripts/sim/demo_agent.py --model claude-sonnet-5-5   # cheaper model
python scripts/sim/demo_agent.py --polite                    # may follow notes for ai agents
```

Default model is `claude-opus-5-5` with summarized thinking, so the screen shows why it runs each command. A typical run is 10 to 20 commands and about a minute. In testing it found `~/README.md` on its own, spotted the note for AI agents, and chose not to run the echo, flagging it in the report instead. Either way the read trips `agent_notice_read` on the trap.

With `--polite`, the system prompt adds that the server's owners know it's an AI agent and that it may follow notes addressed to AI agents. That's the nudge it needs to run the echo from the README, which trips `agent_echo`. Brain then marks the session `harmless` with the dossier "declared itself as an AI agent", so it shows up as a slime instead of a fae.

It uses a pty like paramiko's `invoke_shell` would. Without one, a `sudo` password prompt on the trap closes the channel.

## demo_escalation.py

A scripted session that steps up slowly so the threat climb is watchable: log in, a little recon, `cat /opt/app/.env`, then write a two-line script with `echo` into `/tmp/update.sh`, `chmod +x` it and run it. No downloads. Commands are typed out on screen, with a pause between steps, and after each one it reads the live threat back from the API.

| step | threat |
| --- | --- |
| connect | low (only for a moment, see below) |
| login, recon | med |
| `cat /opt/app/.env` | high (the team user gets "Permission denied", but the attempt counts) |
| `chmod +x /tmp/update.sh`, run it | critical (a file it wrote itself, made executable) |

```
python scripts/sim/demo_escalation.py
python scripts/sim/demo_escalation.py --pause 10   # slower, for a live demo
python scripts/sim/demo_escalation.py --no-check   # skip the api reads
```

It's tagged as simulated by its ssh client string, `HackTXSim_1.0 simulated-escalation`, which shows up as `attacker.client` on every event. The trap holds a session's events until login settles its source, so the connect (low) and login (med) events arrive together.
