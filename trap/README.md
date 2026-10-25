# trap

The honeypot. Runs on its own isolated server. asyncssh SSH server on port 22, FastAPI fake web pages on port 80, and a fake shell (rules engine first, LLM fallback) over a virtual filesystem. It never executes attacker input. It sends raw events to `POST https://api.<domain>/ingest`, shaped like `contracts/raw_event.schema.json`.

Right now the SSH server and the rules engine are done. Events go to a local spool file; the HTTPS sender, LLM fallback and fake web pages come later.

## Run it locally

Needs Python 3.11 or newer (`py -3.12` on Windows).

```sh
cd trap
py -3.12 -m venv .venv            # or python3.12 -m venv .venv
.venv/Scripts/activate            # or source .venv/bin/activate
pip install -e ../contracts/py -e ".[dev]"
python -m honeypot
```

It listens on port 2222. Log in with any pair from `honeypot/data/logins.json`:

```sh
ssh -p 2222 -o UserKnownHostsFile=/dev/null root@localhost   # password: root
```

Every session lands in `state/spool.jsonl` as raw events, one JSON object per line. Host keys are generated into `state/host_keys/` on first start and reused after, so the fingerprint stays the same. `state/` is git-ignored.

## Tests

```sh
cd trap
python -m pytest
```

`tests/test_ssh.py` starts the real server on a random localhost port and logs in with an asyncssh client. `tests/test_safety.py` scans `honeypot/` and fails on anything that could run or connect on the host (subprocess, os.system, eval, exec, socket and friends).

## Config

All from env vars. See `.env.example` at the repo root.

| var | default | what |
| --- | --- | --- |
| `TRAP_SSH_HOST` | `0.0.0.0` | listen address |
| `TRAP_SSH_PORT` | `2222` | listen port (22 in production) |
| `TRAP_STATE_DIR` | `state` | host keys and spool |
| `TRAP_LOGINS_PATH` | `honeypot/data/logins.json` | allowed default logins |
| `GUEST_SSH_USER`, `GUEST_SSH_PASSWORD` | unset | demo login, marks the session `guest` |
| `TEAM_SSH_USER`, `TEAM_SSH_PASSWORD` | unset | our login, marks the session `team` |
| `TEAM_IPS` | unset | comma separated ips that always count as `team` |
| `TRAP_MAX_CONNECTIONS` | `200` | connections past this are closed right away |
| `TRAP_MAX_SESSIONS_PER_CONN` | `10` | channels per connection |
| `TRAP_LOGIN_TIMEOUT` | `60` | seconds to finish logging in |
| `TRAP_IDLE_TIMEOUT` | `300` | seconds of no input before auto-logout |
| `TRAP_HARD_TIMEOUT` | `1800` | max seconds per connection |

A guest or team login only works when both its user and password are set.

## What the SSH server allows

- Password and keyboard-interactive login only. Public keys are declined.
- Interactive shells and exec commands, both answered by the rules engine.
- Refused: local and remote port forwarding, unix socket forwarding, agent forwarding, X11, SFTP, SCP, rsync and every other subsystem.
- Passwords are compared and dropped. Only the username and a success flag reach the events.

## Layout

```
honeypot/
  config.py        env -> Settings
  auth.py          login check and source (wild, guest, team)
  events.py        raw events via hacktx_contracts, jsonl spool
  ssh_server.py    asyncssh server, limits, refusals
  main.py          python -m honeypot
  vfs.py           read-only base fs + copy-on-write overlay per session
  shell/           parser, rules engine, commands
  data/            logins, fs seed, system facts
```
