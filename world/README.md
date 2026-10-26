# Breadcrumbs world

The frontend: Next.js App Router, TypeScript, CSS Modules. Three.js through React Three Fiber and Drei, Zustand for state, Framer Motion for interface transitions.

## Run

```sh
npm install
NEXT_PUBLIC_MODE=replay npm run dev   # the recorded HackTX attacks, no backend needed
NEXT_PUBLIC_MODE=mock npm run dev     # small fixtures (in dev, ?data=worst or ?data=empty)
NEXT_PUBLIC_MODE=live npm run dev     # a backend at NEXT_PUBLIC_API_URL / NEXT_PUBLIC_WS_URL
```

Open http://localhost:3000. Replay is the default when `NEXT_PUBLIC_MODE` is unset. `.env.example` lists every variable.

Checks: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`.

The live deployment ended after HackTX 2026, and production now runs in replay mode. See the [root README](../README.md#frontend-development) for where things live and how to regenerate the replay snapshot (`npm run snapshot:fetch`, `npm run snapshot:build`).

`node scripts/generate-land.cjs` regenerates the land dots on the globe; provenance is in `src/data/README.md`.
