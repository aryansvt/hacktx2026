# Breadcrumbs world

Next.js App Router, TypeScript, CSS Modules and npm. Three.js uses React Three Fiber and Drei; Zustand owns application state; Framer Motion handles interface transitions.

## Run

```sh
cd world
npm ci
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000. Use `npm run lint`, `npm run typecheck`, and `npm run build` for checks. `npm start` serves a production build.

M0-M4 use `NEXT_PUBLIC_MOCK=1`. M5 will implement the external REST/WebSocket adapter and change the default to `0`; compare this string explicitly. Public backend URLs are recorded in `.env.example`. Do not commit `.env.local`. Vercel Root Directory: `world`. Deployment is not part of these milestones.

See ../docs/frontend-progress.md and the companion specs for scope and delivery status.

## M1 live core

Open `/live` (the temporary root redirects there until M3). Mock mode streams a deterministic finite scenario with overlapping visits, all four kinds, slime/elite/dragon variants, and an empty-command visit. The adapter keeps the replay response as `{session, events}`. Mock events never increment wild counters; the timeline is labeled mock history. Live stays unavailable until M5.

`npm test` checks fixtures against the repository JSON Schemas and exercises grouping, overlapping visits, deduplication, ping rejection, wrapped replay, unknown classification retention, navigation, and explicit mock configuration. `node scripts/generate-land.cjs` regenerates the local land dots; provenance lives in `src/data/README.md`.

M2 supplies the currently disabled controls. M3 supplies the public website pages. M4 replaces the explicit octahedron/icon placeholders and adds richer event animation. M5 supplies runtime validation, reconciliation, REST/WebSocket transport, and live mode. Nothing here sends commands to the trap.
