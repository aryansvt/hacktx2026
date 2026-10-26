# Replay Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make followthebreadcrumbs.tech work with no backend by replaying an anonymized snapshot of real HackTX 2026 attacks, and leave the repo runnable and documented after the servers go away.

**Architecture:** A build script turns a raw API dump into `world/public/replay/snapshot.json`. A third `DataAdapter` (`replay`) schedules those events on a loop, restamps them to now, and re-hydrates the store every lap. Mode comes from `NEXT_PUBLIC_MODE`.

**Tech Stack:** Next.js 16, React 19, zustand, node:test via tsx, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-26-replay-mode-design.md`

## Global Constraints

- Banner copy, exact: "Replaying real attacks recorded during HackTX 2026. The live trap is offline."
- No em dashes in copy or docs. Short lowercase code comments.
- Replay mode makes no request to the old API host, ever.
- Snapshot events validate against `contracts/event.schema.json`.
- Run `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` in `world/` before merging.
- Never commit the raw dump or any secret.

## Review Focus

- A visitor whose localStorage still says "live" from the event: must land in replay, not the dead API. Test in Task 3.
- A tab left in the background for an hour: must not flood events on return. Test in Task 2 (clock pauses while hidden).
- A creature page opened for a session from the previous lap, or for one still playing: must load, and never show commands that have not played yet. Test in Task 2.
- A lap boundary: visit counts must not grow and old sessions must not pile up. Test in Task 2.
- Commands with keys, `user:pass | chpasswd`, bait `.env` output or C2 IPs: must come out scrubbed. Test in Task 1.

---

### Task 1: Snapshot builder

**Files:**
- Create: `world/scripts/snapshot/fetch.ts` (done), `world/scripts/snapshot/scrub.ts`, `world/scripts/snapshot/select.ts`, `world/scripts/snapshot/build.ts`
- Create: `world/public/replay/snapshot.json` (generated)
- Modify: `world/.gitignore` (add `/.replay-raw/`), `world/package.json` (scripts `snapshot:fetch`, `snapshot:build`)
- Test: `world/tests/snapshot.test.ts`

**Interfaces:**
- Produces: `type ReplaySnapshot = { version: 1; recorded: { from: string; to: string }; stats: Stats; visits: Record<string, number>; events: AttackEvent[] }` exported from `world/src/lib/replay.ts` (Task 2 owns the file; Task 1 adds the type first).
- Produces: `scrubText(s: string, ips: IpMap): string`, `scrubUrl(url: string): string`, `newIpMap(): IpMap` in `scrub.ts`; `selectSessions(sessions: SessionResponse[], budget: number): SessionResponse[]` in `select.ts`; `anonymize(dump: RawDump, picked: SessionResponse[]): ReplaySnapshot` in `build.ts`; `type RawDump = { fetched_at: string; stats: Stats; attackers: AttackerSummary[]; sessions: SessionResponse[] }`.

- [ ] Step 1: tests: `scrubText` redacts a PEM block, `ssh-rsa AAAA...`, `$6$salt$hash`, `root:Passw0rd|chpasswd`, `DB_PASSWORD=hunter2`, `Authorization: Bearer abc`, an `AKIA` key, an email; maps `wget http://31.56.209.73/x` to a 203.0.113.x address and the same IP to the same address twice; leaves `127.0.0.1` and `uname -a` alone. `scrubUrl` keeps `https://intezer.com/blog/a-post`, cuts `https://www.abuseipdb.com/check/1.2.3.4?x=1` and `https://honeymire.com/attack/1115772` to their origin. `selectSessions` keeps only ended sessions, keeps every dragon and guest, covers every country, stays within budget plus one session. `anonymize` output: every event validates against the schema, no original ip_hash or session id appears anywhere in the JSON, lat/lon have at most 2 decimals, no `guest_name`.
- [ ] Step 2: run `npm test`, see them fail.
- [ ] Step 3: implement. Event ids are random UUIDs ending in `0000`; session ids 32 hex ending in `0000`; ip_hash random 64 hex.
- [ ] Step 4: `npm test` passes. Re-fetch from the live API if it is still up, build the snapshot, check size (under 2 MB) and composition (Kaiji, golems, fae, slimes, guests).
- [ ] Step 5: commit.

### Task 2: Replay adapter

**Files:**
- Create: `world/src/lib/replay.ts`
- Modify: `world/src/lib/contracts.ts` (`DataAdapter.mode` adds `"replay"`; `subscribe(onEvent, control?: AdapterControl)`; `interface AdapterControl { stats?(s: Stats): void; reset?(s: Snapshot): void }`)
- Test: `world/tests/replay.test.ts`

**Interfaces:**
- Produces: `buildSchedule(events: AttackEvent[], targetMs?: number): Schedule` with `Schedule = { lapMs: number; items: { at: number; event: AttackEvent }[]; sessions: Record<string, { start: number; end: number; source: Source }> }`; `lapId(id: string, lap: number): string`; `createReplayAdapter(opts?: { url?: string; load?: () => Promise<ReplaySnapshot>; targetMs?: number }): DataAdapter`.

- [ ] Step 1: tests (node:test mock timers for `setTimeout` and `Date`): schedule keeps recorded order and in-session order, caps in-session gaps at 4 s, lap length near the target; `lapId` keeps UUID shape and differs per lap; `snapshot()` returns one attacker per creature with the recorded visit count, no sessions, no events, real totals, and per_minute ending within a minute of now; events arrive restamped near now; after one lap `reset` is called and the next lap's ids differ; visit counts after folding a full lap plus the reset stay at the recorded value; `session(id)` for the current lap returns only events already played; a hidden tab (stubbed `document.hidden`) pauses emission; `stats` pushes `active_now`.
- [ ] Step 2: run, fail.
- [ ] Step 3: implement.
- [ ] Step 4: pass. Commit.

### Task 3: Mode selection and shell wiring

**Files:**
- Modify: `world/src/lib/data-mode.ts`, `world/src/components/live/LiveShell.tsx`, `world/src/lib/live.ts` (localhost defaults), `world/tests/core.test.ts`, `world/tests/modes.test.ts`, `world/.env.example`

**Interfaces:**
- Produces: `type DataMode = "live" | "mock" | "replay"`; `envMode(mode?: string, mock?: string): DataMode`; `allowedModes(env: DataMode): DataMode[]`; `useMode` zustand store `{ mode: DataMode | null }`.

- [ ] Step 1: tests: `envMode("replay")`, `envMode("live")`, `envMode("mock")`, `envMode(undefined, "1") === "mock"`, `envMode(undefined, undefined) === "replay"`, `envMode("nonsense") === "replay"`; `allowedModes("replay")` excludes live; `allowedModes("live")` includes all three.
- [ ] Step 2: fail, implement, pass.
- [ ] Step 3: LiveShell creates the replay adapter, passes `{ stats: setStats, reset: hydrate }`, select shows only allowed modes.
- [ ] Step 4: commit.

### Task 4: Replay copy and banner

**Files:**
- Create: `world/src/components/live/ReplayBanner.tsx` (+ styles in `live.module.css`)
- Modify: `Timeline.tsx`, `WebIntel.tsx`, `Oracle.tsx`, `CreaturePage.tsx`, `Footer.tsx`, `TopBar.tsx`, `Heralds.module.css`

- [ ] Step 1: banner in the top left on desktop, hidden while `surface !== "none"`; full width under the top bar on phones with heralds pushed below via a CSS variable set on the shell.
- [ ] Step 2: copy swaps listed in the spec.
- [ ] Step 3: run dev in replay mode, screenshot 1440 and 390, review-animations critique, break-ui pass, iterate.
- [ ] Step 4: lint, typecheck, test, build. Commit.

### Task 5: Local stack

**Files:**
- Create: `docker-compose.yml` (repo root), `world/Dockerfile`, `world/.dockerignore`
- Modify: `.env.example`

- [ ] Step 1: compose with timescaledb, redis, backend, brain, trap, world; every published port on 127.0.0.1; dev defaults for INGEST_TOKEN and IP_HASH_SALT; LLM and SerpApi keys optional; a warning header pointing at `infra/`.
- [ ] Step 2: `docker compose config` validates; if Docker is up, `docker compose up --build`, ssh into 127.0.0.1:2222, see the session in `http://127.0.0.1:8000/sessions` and on `http://127.0.0.1:3000`.
- [ ] Step 3: commit.

### Task 6: Docs and leftovers

**Files:**
- Modify: `README.md`, `world/README.md`, `infra/README.md`, `docs/architecture.md`, `docs/frontend-spec.md`, `docs/frontend-implementation-prompt.md`, `CLAUDE.md`
- Delete: `docs/demo-runbook.md`
- Create: `docs/screenshots/*.png`

- [ ] Step 1: README per the user's list (what, win, screenshots, architecture, safety, results, run locally, frontend development, snapshot regeneration, live deployment ended and data deleted).
- [ ] Step 2: strip the old API host, Vultr specifics and server runbook steps.
- [ ] Step 3: commit.

### Task 7: Ship

- [ ] Step 1: secret scan the branch commits (gitleaks in Docker if available, plus pattern grep).
- [ ] Step 2: merge to main, set `NEXT_PUBLIC_MODE=replay` on Vercel production, push main.
- [ ] Step 3: wait for the deploy, load followthebreadcrumbs.tech with the API host blocked, confirm zero API requests, screenshots at both widths.
