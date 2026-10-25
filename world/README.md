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
