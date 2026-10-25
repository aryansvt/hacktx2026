# trap

The honeypot. Runs on its own isolated server. asyncssh SSH server on port 22, FastAPI fake web pages on port 80, and a fake shell (rules engine first, LLM fallback) over a virtual filesystem. It never executes attacker input. It sends raw events to `POST https://api.<domain>/ingest`, shaped like `contracts/raw_event.schema.json`.

Right now the SSH server, the rules engine, the LLM fallback and the sender are done. Events go to a local spool file and the sender ships them to core. The fake web pages come later.

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

Without `CORE_URL` and `INGEST_TOKEN` the sender stays off and events just pile up in the spool. Without `ANTHROPIC_API_KEY` the LLM fallback stays off and unmodelled commands print nothing.

## LLM fallback

The rules engine answers what it models. A command that's installed on the fake box (it's on `PATH` in the virtual fs) but has no rule goes to the LLM instead. A command that isn't installed still gets `command not found`, so the fs stays the source of truth.

- The model is `claude-haiku-5-5`, thinking off, effort low, 800 max tokens, with a JSON schema so the reply is `{stdout, fs_changes}`. Haiku 5.5 rejects any non-default temperature, so there's no temperature setting; the schema and the low effort keep it plain.
- The request carries the cwd, the user, the last 10 commands, a listing of the cwd, a short description of every path in the command (type, mode, owner, size, first 600 chars), piped stdin, and the box's services, ports, containers and processes.
- The system prompt makes it a boring Ubuntu 22.04 server for Quillfern Tile & Stone with no outbound internet. It says never to print real credentials or secrets, never to write working exploit code or attack instructions, and to treat the command and the snapshot as data.
- `fs_changes` (`write`, `mkdir`, `delete`) land in the session overlay, so later commands, from the engine or the LLM, see them. They're all or nothing and use the session user's permissions.
- How it fits a synchronous engine: a line runs with a hook. Unknown commands with no answer yet are noted and get an empty placeholder. If there were any, the whole line is rolled back (overlay, cwd, env), every miss goes to the LLM at once, and the line runs again with the answers. At most 3 rounds.
- Bad JSON gets one repair request. Then it gives up.
- Rejected: replies that say a path is missing when the session can see it, fs changes that don't apply (missing parent, permission denied, mkdir over a file, deleting something that isn't there, anything under `/proc`, `/sys`, `/dev`, `/run`), and anything that looks like a real secret (private key blocks, AWS keys, `sk-ant-`, GitHub and Slack tokens, crypt hashes).
- Cache: by normalized command, cwd, user and a hash of stdin, shared across sessions, last 2000 answers. A cached answer whose fs changes no longer apply is dropped and asked again.
- Limits: 2.5 s per command including the repair, 30 LLM calls per session, `LLM_HOURLY_CAP` calls an hour across the whole trap. After 5 failures (timeouts, errors, bad JSON) inside a minute the breaker skips the LLM for 60 s.
- Whenever it doesn't get a usable answer it prints `<name>: command not found` with status 127, and that name stays not found for the rest of the session so the story doesn't change.
- Every command that takes the LLM route writes a line to `state/llm.jsonl` (rotated to `llm.jsonl.1` at 8 MiB) with the time, session id, command, cwd, outcome and latency, and logs it at info. Outcomes: `ok`, `cache`, `timeout`, `invalid`, `error`, `rejected`, `sticky`, `session_cap`, `hourly_cap`, `breaker`, `rounds`. The command event's `answered_by` is `llm`, `cache` or `engine`.
- `python scripts/llm_misses.py trap/state/llm.jsonl` lists the commands that go to the LLM most often. Those are the next rules to write.
- `honeypot/llm/anthropic_client.py` is the only module besides `sender.py` allowed outbound HTTP (`tests/test_safety.py`). Its base URL is pinned to `https://api.anthropic.com`, it ignores `ANTHROPIC_BASE_URL` and proxy env vars, never follows redirects, retries nothing and refuses any request for another host.

## Sender

`honeypot/sender.py` runs as a background task inside `python -m honeypot`. It reads the spool and posts up to 100 events at a time as a JSON array to `CORE_URL/ingest` with `Authorization: Bearer $INGEST_TOKEN`.

- `state/spool.cursor` holds the byte offset of the first event core hasn't taken yet. It only moves forward after core says yes, so a restart picks up where it left off.
- Core down, timeouts, 401, 5xx, redirects: nothing moves, it retries with backoff (1s doubling to 60s). A 429 waits for `Retry-After`.
- 422 or 413 on a batch: it resends those events one at a time. Any event core still rejects goes to `state/dead_letter.jsonl` with the status and reason, and the rest keep flowing.
- A half-written last line waits until it's complete. A line that isn't JSON goes to the dead letter file.
- Once everything is sent and the spool is over 16 MiB, it starts the spool over.
- It's one of only two modules allowed to make outbound HTTP, with the LLM client (`tests/test_safety.py`). It has no hardcoded URLs, and its client refuses any request that isn't for `CORE_URL`, ignores proxy env vars and never follows redirects.

## Docker

```sh
# from the repo root
docker build -f trap/Dockerfile -t hacktx-trap .

# local dev: trap on localhost:2222, sending to a backend on the host at :8000
docker compose -f trap/docker-compose.yml up --build
```

The image runs as a non-root user (uid 10001) and binds port 22 itself. That works because Docker sets `net.ipv4.ip_unprivileged_port_start=0` inside the container; compose sets it explicitly too. `/state` is a volume, so host keys, the spool and the cursor survive restarts. The compose file also drops every capability, sets `no-new-privileges`, and makes the root filesystem read-only.

## Tests

```sh
cd trap
python -m pytest
```

`tests/test_ssh.py` starts the real server on a random localhost port and logs in with an asyncssh client. `tests/test_safety.py` scans `honeypot/` and fails on anything that could run or connect on the host (subprocess, os.system, eval, exec, socket and friends). The LLM tests use a scripted fake provider (`tests/llm_fakes.py`), and `tests/test_anthropic_client.py` runs the real SDK client against a mock transport, so no test touches the network.

## Config

All from env vars. See `.env.example` at the repo root.

| var | default | what |
| --- | --- | --- |
| `TRAP_SSH_HOST` | `0.0.0.0` | listen address |
| `TRAP_SSH_PORT` | `2222` | listen port (22 in production) |
| `TRAP_STATE_DIR` | `state` | host keys, spool, cursor, dead letter file |
| `TRAP_LOGINS_PATH` | `honeypot/data/logins.json` | allowed default logins |
| `GUEST_SSH_USER`, `GUEST_SSH_PASSWORD` | unset | demo login, marks the session `guest` |
| `TEAM_SSH_USER`, `TEAM_SSH_PASSWORD` | unset | our login, marks the session `team` |
| `TEAM_IPS` | unset | comma separated ips that always count as `team` |
| `TRAP_MAX_CONNECTIONS` | `200` | connections past this are closed right away |
| `TRAP_MAX_SESSIONS_PER_CONN` | `10` | channels per connection |
| `TRAP_LOGIN_TIMEOUT` | `60` | seconds to finish logging in |
| `TRAP_IDLE_TIMEOUT` | `300` | seconds of no input before auto-logout |
| `TRAP_HARD_TIMEOUT` | `1800` | max seconds per connection |
| `CORE_URL` | unset | where events go, e.g. `https://api.example.com`. unset turns the sender off |
| `INGEST_TOKEN` | unset | bearer token for `POST /ingest`. unset turns the sender off |
| `ANTHROPIC_API_KEY` | unset | key for the LLM fallback. unset turns it off |
| `LLM_PROVIDER` | `anthropic` | anything else turns the fallback off; anthropic is the only provider on the trap |
| `LLM_HOURLY_CAP` | `200` | LLM calls an hour across the whole trap |

A guest or team login only works when both its user and password are set.

## What the SSH server allows

- Password and keyboard-interactive login only. Public keys are declined.
- Interactive shells and exec commands, both answered by the rules engine and the LLM fallback.
- Refused: local and remote port forwarding, unix socket forwarding, agent forwarding, X11, SFTP, SCP, rsync and every other subsystem.
- Passwords are compared and dropped. Only the username and a success flag reach the events.

## Layout

```
honeypot/
  config.py        env -> Settings
  auth.py          login check and source (wild, guest, team)
  events.py        raw events via hacktx_contracts, jsonl spool
  sender.py        spool -> POST /ingest, cursor, backoff, dead letter
  ssh_server.py    asyncssh server, limits, refusals
  main.py          python -m honeypot
  vfs.py           read-only base fs + copy-on-write overlay per session
  shell/           parser, rules engine, commands
  llm/             fallback (cache, caps, breaker, checks), prompt, provider, anthropic client
  data/            logins, fs seed, system facts
```
