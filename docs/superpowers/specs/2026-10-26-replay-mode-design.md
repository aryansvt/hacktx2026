# Replay mode and post-event cleanup

Date: 2026-10-26. Status: approved (self-approved under the "decide yourself" rule).

## Why

Breadcrumbs won HackTX 2026 and the trap and core servers are being shut down. The site at followthebreadcrumbs.tech has to keep working with no backend, show real attacks from the event, and stay honest about being a recording. A future backend must still be able to plug back in.

## Goals

- A committed, anonymized snapshot of about 2000 real events in `world/public/replay/`, covering the Kaiji dragon, stone golems, fae, slimes, guest knights, dossiers and stories.
- `NEXT_PUBLIC_MODE=replay` plays the snapshot on a loop. Globe, chronicle, heralds, oracle, creature pages and Beneath the Castle all work. No request goes to the old API.
- Live and mock adapters stay as they are, picked by env flag.
- A small banner: "Replaying real attacks recorded during HackTX 2026. The live trap is offline."
- Production on Vercel runs replay mode, verified with the API host blocked.
- README, `.env.example`, local docker compose (localhost only), removal of server-specific leftovers, secret scan.

## Non-goals

- No new UI features beyond the banner and the copy that has to change ("LIVE" badge, "live web reputation lookup").
- No changes to trap, brain or backend behavior.

## Anti-goals

- Anything that reaches the old API in replay mode, including a stale "live" choice in localStorage.
- Raw IPs, hashed IPs that could be joined back, passwords, keys or tokens in the committed snapshot.
- Inflated numbers: visit counts and totals must match what was recorded.

## Snapshot

Two committed scripts in `world/scripts/snapshot/`:

- `fetch.ts` pulls `/stats`, `/attackers` and `/sessions` per source, then every reachable `/sessions/{id}`, into a raw dump that stays out of git (`world/.replay-raw/`, gitignored).
- `build.ts` turns a raw dump into `world/public/replay/snapshot.json`. Selection and scrubbing are pure functions with tests.

Selection: whole sessions only (never half a visit), only sessions that ended. Score by creature (dragon, stone golem, guest, slime, fae, then shadows and plain bots), plus dossier, tripwire, family, breach, LLM answers and command count. Every recorded country gets at least one session, very noisy attackers are capped at a few sessions, and the rest fills by score until about 2000 events.

Anonymization:

- Every ip_hash becomes a random 64-hex id, every session id a random id, every event id a random UUID.
- Fields are limited to what the UI reads (the event contract), with lat/lon rounded to 2 decimals.
- Text (commands, outputs, usernames, reasons, stories, dossier summaries and titles) is scrubbed: PEM blocks, SSH keys, crypt hashes, `user:pass | chpasswd`, `KEY=value` where the key looks like a password, secret, token or key, bearer and auth headers, JWTs, cloud keys, emails, and every non-loopback IP (mapped to documentation ranges, consistently within the snapshot).
- Dossier source URLs keep the full path only when it carries no IP, long number or hash; otherwise they shrink to the site's origin.
- Guest names are dropped.

Snapshot file: `{ version, recorded: {from, to}, stats, visits, events }`. `stats` are the real wild totals at export. `visits` is the real visit count per re-keyed creature, so creature pages show what was recorded.

## Replay adapter

`world/src/lib/replay.ts`, implementing the existing `DataAdapter`.

- Schedule: sessions in recorded order. Gaps between session starts are scaled and clamped so a lap lasts about 12 minutes. Gaps inside a session keep real timing, capped at 4 s.
- Each emitted event is restamped to the current time, so relative times, the walk to the gate and events per second behave like live.
- Lap k rewrites the last 4 hex digits of event and session ids, so laps never collide in the store.
- `snapshot()` returns every creature as an attacker summary (as of the previous lap, real visit counts), no sessions or events, and the real stats with the per-minute history shifted to end now.
- At each lap boundary the adapter asks the shell to re-hydrate with that base, so sessions never pile up and visit counts never inflate.
- `session(id)` serves any lap's session, current lap only up to now.
- `active_now` comes from the schedule and is pushed through a new optional stats callback.
- The clock pauses while the tab is hidden, so coming back never floods the page.

`DataAdapter.subscribe(onEvent, control?)` gains an optional second argument `{ stats?, reset? }`. Live and mock ignore it.

## Mode selection

`NEXT_PUBLIC_MODE` = `replay | live | mock`. Unset falls back to `NEXT_PUBLIC_MOCK=1` (mock) and otherwise replay, since the backend is gone. The hidden M toggle offers Live only when the build is in live mode, and a stored choice is ignored unless it is allowed. Live defaults point at localhost instead of the old API host.

## UI copy in replay mode

- Banner, top left under the top bar on desktop (hidden while the creature page or chronicle feed fills that column), full width under the top bar on phones with heralds moved below it.
- Timeline badge reads REPLAY. "live web reputation lookup" reads "recorded web reputation lookup".
- Footer: the live deployment ended and its data was deleted; this is an anonymized recording.
- Top bar tooltips talk about the recording, not "right now on the server".

## Left to the builder

Exact lap length, banner styling within the parchment look, scoring weights.
