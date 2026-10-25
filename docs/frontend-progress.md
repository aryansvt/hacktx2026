# Frontend progress

## M0: scaffold — delivered
- Scope: Next.js App Router + TypeScript in world/, npm lockfile, CSS Modules, required 3D/state/motion dependencies, environment example and run instructions.
- Checks: lint, typecheck, production build and generated application browser startup passed.
- Commit: 18c323c. Pushed branch: codex/world-m0-scaffold.
- PR: https://github.com/aryansvt/hacktx2026/pull/6 into world. No dependency. Merged externally on October 25, 2026.
- Read CLAUDE.md and public contracts from confirmed origin/main b87780c7f384f5216d7702c04f89057ff9da358e before domain work. Supplied documents and render artifacts preserved.

## M1: live core — implemented and verified; remote delivery pending
- Scope: persistent Three.js globe, P2 styling within wiring geometry, collapsed Latest activity, Activity and map-linked creature inspection with Replay, Details and Dossier subviews.
- Contract-aligned deterministic mock adapter, normalized Zustand domain state, separate navigation/selection state, repeated and overlapping visits, all event kinds, elite/dragon fixtures, empty-command replay, and early ping exclusion.
- Mock is visibly labeled; wild-only counters stay zero. Live is unavailable until M5. Public API configuration is recorded without connecting to the backend.
- Checks: lint, typecheck, production build and six contract/domain tests passed. Production browser navigation, keyboard/focus, panel geometry and 1920x1080/1280x800 layouts verified. Zero console errors; one upstream THREE.Clock deprecation warning remains.
- Independent visual reviewer: ship M1; nine production captures reviewed. No automated pixel-diff or real-backend validation claimed. See verification/m1.md and frontend-design.md.
- Branch: codex/world-m1-live-core, advanced to origin/world 9b2f5f2 after M0 merged. PR target: world. Prerequisite: merged PR #6.
- Limitations: creature geometry is intentionally placeholder M1 scope; advanced controls, Event Log, website pages, asset polish and backend integration remain for later milestones. Reduced-motion handling reviewed in source; OS preference was not changed during browser validation.

## Remaining milestones
- [ ] M2 controls and Event Log.
- [ ] M3 website pages.
- [ ] M4 world assets and polish.
- [ ] M5 real backend integration.

M0-M4 use NEXT_PUBLIC_MOCK=1. No merge or deployment performed by this task.
