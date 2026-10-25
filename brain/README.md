# brain

Runs on core. Reads raw trap events from Redis stream `raw`, works out who the attacker is, and writes public events to Redis stream `events`. Every event it writes is checked against `contracts/event.schema.json` first.

For each raw event it:

- looks up where the attacker is (GeoLite2 City, rounded to 2 decimals) and who owns the network (GeoLite2 ASN)
- swaps the raw IP for `ip_hash` and drops raw fields that aren't in the public schema (`src_ip`, `input`, `success`, `client` in detail)
- maps commands to MITRE ATT&CK technique ids
- updates the threat level and the bot / human / agent classification

It also makes three event types of its own:

- `classified` when the label changes or confidence moves by 0.15 or more
- `dossier` when a web reputation lookup finishes
- `story` after `session_end`

## Stream format

Both streams use one field, `data`, holding the event as JSON.

```
XADD raw * data '{"event_id": "...", "type": "command", ...}'
XREAD STREAMS events 0   ->  data '{"event_id": "...", "geo": {...}, "attacker": {...}, ...}'
```

Brain reads `raw` through the consumer group `brain`. On startup it finishes any messages it read but never acked, so a restart doesn't lose events. Each processed `event_id` gets a marker for 24 hours, so a replayed message isn't counted twice. Messages that aren't valid JSON or don't match `raw_event.schema.json` go to `raw:dead` with the reason.

Passthrough events keep the trap's `event_id`. Events brain makes itself use a uuid5 of the source event id, so a replay produces the same id and backend can dedupe on it.

## How each piece works

**Geo** (`geo.py`). Unknown or private IPs get country `XX` and a point in the mid Atlantic with a small spread so they don't stack up. Guest and team sessions use `TABLE_LAT` / `TABLE_LON` (Austin).

**Classifier** (`classifier.py`). Plain rules, no trained model. Each signal is a small function that returns a label, a weight key and a reason. Weights live in `WEIGHTS` at the top of the file. The winner's share of the total weight, scaled down until there's enough evidence (`MIN_EVIDENCE`), is the confidence. A session stays `unknown` until it has run a command, hit a tripwire or made 3+ login attempts, and the winner has at least two signals behind it. The top 2 to 4 reasons go out with the event.

One exception: a quick login-only scan. If a session ends within `QUICK_SCAN_S` (5 seconds) after one or more logins and no commands, and its SSH client is a scripting library (Go, libssh, paramiko, JSch, AsyncSSH, Twisted, ZGrab and similar), it's labeled `bot` at 0.7 with reasons like "scanner SSH client (Go)" and "tried 1 login in under a second, then left". OpenSSH, PuTTY and unknown clients still stay `unknown`.

The other exception: an IP that keeps coming back. Brain keeps a sorted set per `ip_hash` in Redis (`brain:visits:<ip_hash>`, session ids scored by start time, one-hour TTL). When `REPEAT_VISITS` (10) or more wild sessions from one `ip_hash` started in the last hour, an ended session is labeled `bot` at 0.75 with "connected N times in the last hour" as the first reason, whatever its SSH client. The count is taken when a session starts and again at `session_end`, so visits that arrive meanwhile count too. It also adds bot weight to the normal score. The 0.75 label only replaces an `unknown` or weaker `bot` verdict, never a human or agent one. Guest, team and mock sessions aren't counted, since people at our table can share one IP. On `session_end`, the `classified` event goes out before the `session_end` event so the globe and the story use the final label.

| Signal | Leans | Why |
| --- | --- | --- |
| sub-second, regular gaps between commands | bot | scripts don't pause |
| steady multi-second gaps | agent | waiting on a model each step |
| irregular gaps with idle spikes | human | people think, get distracted |
| known bot scripts, long `;` one-liners | bot | fixed recon and dropper scripts |
| typos, backspaces, `clear`, editors, cd/ls wandering | human | people explore and fumble |
| reading READMEs and `--help`, readable `&&` chains | agent | agents read docs first |
| using paths that first appeared in docs it read | agent | follows instructions in text |
| tripwire hit | agent | strongest agent signal |
| Go / libssh / zgrab client | bot | |
| paramiko / asyncssh client | bot + agent | scripted |
| OpenSSH / PuTTY client | human + agent | interactive |
| rapid failed logins, dictionary usernames | bot | credential spraying |
| hosting network, research scanner network | bot | rented boxes and scanners |
| 10+ sessions from one `ip_hash` in the last hour | bot | people don't reconnect that often |

To tune it, change a weight or threshold, then run `python -m pytest tests/test_classifier.py`. The bot, human and agent fixtures in `tests/fixtures/` pin the expected labels.

**Threat** (`threat.py`). Failed logins only is `low`. Getting in is `med`. Reading credentials or `.env` files, downloading, or persistence (cron, ssh keys, new users) is `high`. Running a downloaded payload, crypto miners, or wiping logs and history is `critical`. So is a hand-written dropper: a file written with `echo`, `printf`, `cat` or `base64 -d` and `>`/`>>`, or with `tee`, that is then made executable (`chmod +x`, `chmod 755`) or run (`./x`, `sh x`, `bash x`), in the same line or later. Writing to crontab, `authorized_keys`, `rc.local` or systemd units stays `high`, even by a relative path. A malicious reputation bumps it one level. It never goes down.

**Techniques** (`techniques.py`). A lookup table from command names and patterns to ATT&CK ids, like `uname` to T1082, `cat /etc/passwd` to T1087.001, `wget` to T1105 and `crontab` to T1053.003.

**Reputation** (`reputation.py`). Only for `wild` sessions that logged in, hit a tripwire or downloaded something, so plain scans don't burn searches. It searches the attacker IP first, once per session, then domains and tool names from commands, up to 4 lookups per session. A tool name only counts if it was run as a program (`./x`, `sh x`, `bash x`), made executable (`chmod +x x`) or downloaded (a `wget` or `curl` target). Names shorter than 4 characters, shell builtins, standard Linux commands and common English words like `filter` or `update` are skipped. It only sends search strings to SerpApi and never visits attacker URLs. The LLM reads the results and returns `{reputation, family, summary, sources}`. Sources must be links that were actually in the results. The attacker IP is replaced with `[the ip]` before the LLM sees anything, and links containing it are dropped. Results are cached in Redis and in the Tiger Data table `reputation_cache` for 7 days. IP lookups are keyed by the salted hash, so raw IPs never reach Tiger Data. `SERPAPI_HOURLY_CAP` limits searches per hour. Networks of known research scanners (Censys, Shodan and similar) start out `harmless`.

**Story** (`story.py`). After `session_end` it waits up to 10 seconds for lookups still running, then asks the LLM for 2 to 4 storybook sentences using the creature and the city. Bots are clay golems (stone golems if malicious), humans are dark mages (evil witches if malicious), AI agents are fae (cursed fae if malicious), unknowns are shadowy strangers, harmless visitors are slimes and critical ones are dragons. The first mention of the creature is followed by what it really is in parentheses, like "a clay golem (bot)". If the LLM leaves that out, brain adds it. IPs are scrubbed from the result. If the LLM is missing, over its cap or fails, a template story goes out instead.

**LLM** (`llm.py`). `LLM_PROVIDER=anthropic` uses `BRAIN_ANTHROPIC_MODEL` (default `claude-opus-5-5`) at low effort, with server-side refusal fallbacks turned on, since honeypot logs can trip safety classifiers. `LLM_PROVIDER=gemini` uses `BRAIN_GEMINI_MODEL`. Every call counts against `LLM_HOURLY_CAP`.

## Config

All env vars are in the root `.env.example`. Brain reads:

| Var | Use |
| --- | --- |
| `REDIS_URL` | streams, session state, caches, caps |
| `TIGER_DATABASE_URL` | `reputation_cache` table (optional, Redis only without it) |
| `IP_HASH_SALT` | required, brain won't start without it |
| `GEOIP_DB_PATH`, `GEOIP_ASN_DB_PATH` | GeoLite2 City and ASN files (optional, falls back to `XX`) |
| `TABLE_LAT`, `TABLE_LON` | geo for guest and team sessions |
| `LLM_PROVIDER`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` | dossier verdicts and stories (optional, templates without) |
| `BRAIN_ANTHROPIC_MODEL`, `BRAIN_GEMINI_MODEL` | model ids |
| `SERPAPI_KEY` | reputation lookups (optional, none without) |
| `SERPAPI_HOURLY_CAP`, `LLM_HOURLY_CAP` | spend caps per hour |
| `BRAIN_CONSUMER` | consumer name in the `brain` group |
| `BRAIN_SESSION_TTL_S` | how long session state lives in Redis (default 1 day) |

## Run

```bash
pip install -e contracts/py -e "brain[dev]"
python -m brain
```

Docker, built from the repo root:

```bash
docker build -f brain/Dockerfile -t hacktx-brain .
docker run --env-file .env -v "$PWD/data:/data:ro" hacktx-brain
```

## Backfill

`scripts/backfill_classify.py` is a one-time fix for sessions stored before a classifier change, like the quick login-only scan rule. It finds every ended session in Tiger Data that is still `unknown`, rebuilds it from its stored public events and runs the classifier again. For each session that now gets a label, it writes a `classified` event to the Redis stream `events`. The backend stores it, updates the session and broadcasts it on `/live` like any other event.

```bash
TIGER_DATABASE_URL=... REDIS_URL=... python brain/scripts/backfill_classify.py --dry-run   # only print counts
TIGER_DATABASE_URL=... REDIS_URL=... python brain/scripts/backfill_classify.py
```

- Public events have no raw IP or network owner, so the hosting and scanner network signals are missing from the rerun. Everything else the classifier reads is stored.
- Session timing only uses events the trap saw. Story and dossier events are stamped later and would make a 0.3 second scan look slow.
- Repeat visits are counted from the `sessions` table: wild sessions from the same `ip_hash` that started in the hour before the session ended. Same window and rule as the live Redis count.
- The new event gets the session's latest stored timestamp. That way the backend takes the new label without moving the session's `last_seen`.
- Event ids are derived from the session id, so running it twice never double counts.

## Test

```bash
cd brain
python -m pytest
```

Tests use fakeredis and mock SerpApi, the LLM and Tiger Data, so they need no network or keys.
