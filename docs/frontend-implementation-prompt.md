# Breadcrumbs: Figma MCP to frontend

Use the kickoff prompt below to establish the project and first frontend milestone. Each milestone ends with verified code, a commit, a push and its own pull request (PR). Develop the frontend with contract-shaped mock data first; connect the existing backend after frontend development is complete.

## Kickoff prompt - copy this block

```text
Implement Breadcrumbs in milestones using my Figma design, the companion specs and the Git workflow below. Complete Milestone 0 and Milestone 1 in this kickoff; later prompts define the remaining milestones.

Milestone and Git delivery workflow
- Repository: https://github.com/aryansvt/hacktx2026.git. Inspect the current directory first. Reuse an existing checkout of this repository; clone only if it is absent. Never clone into an existing nonempty directory or create a duplicate nested checkout. Preserve these supplied docs when moving into the real checkout.
- Use world as the frontend integration branch, as requested. If origin/world exists, track/reuse it; otherwise create world from the confirmed current origin/main. Preserve unrelated uncommitted changes and never force-push or reset someone else's work.
- For one PR per milestone without repeatedly including earlier milestones, use feature branches codex/world-m0-scaffold, codex/world-m1-live-core, codex/world-m2-controls, codex/world-m3-pages, codex/world-m4-polish, codex/world-m5-integration. Reuse an explicitly supplied user feature branch when requested. Do not push implementation commits directly to main.
- Each feature branch starts from the preceding milestone's completed head. Open M0's PR into world; open each later milestone's PR into its preceding milestone branch while it is unmerged. If that predecessor is already merged, branch from the updated world and target world. This keeps each PR limited to one milestone and allows continued work without waiting for merges. Record dependencies and retarget stacked PRs when their predecessor merges.
- At EVERY milestone: finish its scope, run the relevant checks and browser verification, update docs/frontend-progress.md, review the diff, stage only milestone files, commit with a descriptive message, push the feature branch with upstream tracking, and create a PR with the correct base branch. Attach the created PR to this Codex chat when that capability is available.
- PR descriptions must state the resulting behavior, relevant validation and remaining limitations, and link the prerequisite PR for a dependent milestone. Do not claim tests or visual checks passed unless actually run. Do not commit .env.local, secrets, node_modules or build output.
- Creating commits, pushing milestone branches and creating PRs are authorized by this request. Do not merge PRs or deploy as part of a milestone. If remote/auth access blocks a push or PR, retain the verified local commit, report the exact blocker and mark delivery incomplete; do not fabricate a PR URL.
- End each milestone report with its scope, checks, commit SHA, pushed branch, PR URL/base and dependency. Do not call a milestone delivered until those required actions succeed. Track implementation and remote-delivery status separately if one is blocked.

Milestone 0 - establish world/
- Inspect repository instructions and read CLAUDE.md and contracts/ from the real checkout before defining types.
- Create world/ with create-next-app only if it does not already contain an application. Use App Router and TypeScript; choose options explicitly to match the stack below. Keep the package manager and lockfile consistent. Inspect generated files and avoid a nested Git repository in world/.
- Install the frontend's required dependencies, add run/build/typecheck instructions, .env.example and a short progress checklist. Bootstrap NEXT_PUBLIC_MOCK=1 during frontend development; the real API URLs may be recorded for the later integration milestone.
- Verify the generated app starts and its production build passes, then commit, push and create the M0 scaffold PR before implementing M1. Finish M1 in this kickoff as well.

Context
- Project: Breadcrumbs, a HackTX 2026 honeypot visualization. Internet visitors become creatures on a live 3D globe; users inspect the evidence behind each encounter.
- Confirmed tagline: every attacker leaves a trail. Public site: followthebreadcrumbs.tech. Use this latest handoff copy where older Figma text differs.
- Read docs/frontend-spec.md and docs/architecture.md before editing.
- Figma: https://www.figma.com/design/XJrA0l8ncO2HAKQqUouFo2/hacktx2026?node-id=120-6497
- Layout authority: hacktx2026 > wiring (120:6497). Its standalone screens and prototype connections determine page structure, component placement, panel dimensions, spacing relationships and interactions.
- Styling authority: hacktx2026 > Stylization (173:869) > Medieval Text-Book (177:540) > P2 Blue-Gold (177:541). Reference Landing 177:542, Overview 177:580, and Live event log 177:781. Use this exact variant, not Medieval Modern, Storybook, or another palette.
- Apply the P2 visual style as closely as possible within the wiring layout. Where the references differ structurally, wiring wins. The latest confirmed branding and backend contracts still override outdated example copy/data.
- Inspect repository instructions, current files, package manifest, lockfile, components and assets first. Extend the existing project. If no application exists, scaffold world/ without overwriting the docs.
- The backend is maintained by a teammate. In the actual Git checkout, inspect branch, remotes and uncommitted work, then safely integrate origin/main as appropriate to obtain CLAUDE.md and contracts/. Read those and use the exact event contracts. Use the repository URL supplied above; do not blindly pull or overwrite local changes. Backend connection is a later milestone, but contract alignment starts now.

Required stack
- Next.js App Router with TypeScript, under world/.
- Three.js through @react-three/fiber and @react-three/drei for the actual 3D globe.
- Zustand for normalized application state.
- Framer Motion for short interface transitions, respecting reduced motion.
- Reuse the repository's styling approach and package manager. If none exists, use CSS Modules with shared CSS custom properties. Do not introduce a UI kit solely for this task.
- Keep the frontend compatible with Vercel. The Python/FastAPI/Redis/Tiger Data stack is an external backend described by the architecture, not something to rebuild inside world/.

Figma workflow
1. Use the Figma MCP and the applicable Figma design-to-code skill. Create/reuse the required file session.
2. Read design context and request screenshots for the specific frames before implementing them. Use page metadata to locate nodes rather than dumping the entire page.
3. Inspect the P2 styling frames 177:542, 177:580 and 177:781 with design context and screenshots; extract actual fonts, colors, border treatments, effects and component styling into shared tokens. Then for this first pass inspect overview 120:8390, Activity 120:8573, creature overview 120:9037, Replay 120:9236, Details 120:9421 and Dossier 168:522. Inspect relevant child nodes if context is sparse.
4. Read prototype interactions for entry, close and back behavior. Preserve the source of navigation rather than hardcoding every Back action to overview.
5. Reuse suitable existing components, tokens and Code Connect mappings. Translate generated sample code into maintainable project components; implement the interactions.
6. Download required static assets using the Figma-supported workflow and keep local asset references. Screenshots are comparison targets, never page backgrounds used to impersonate the UI.
7. Read Figma only. This task does not require editing the Figma file.

Design interpretation
- wiring defines structure and behavior. Preserve its proportions, spatial hierarchy and interactions; style the components using Medieval Text-Book / P2 Blue-Gold from Stylization. This explicitly replaces the older dark-theme-only palette requirement.
- Match the selected P2 reference typography (Pirata One, EB Garamond and Inter where used), parchment surfaces, ink, blue/gold accents, borders, buttons and decorative details. Read exact styles from the nodes rather than inventing a generic medieval theme. Keep dense data readable.
- Do not import a styling frame's layout in place of wiring. Fit its visual treatments to wiring's components, preserve panel bounds and globe safe areas, and use internal scrolling for text overflow. For states without P2 equivalents, compose shared P2 tokens consistently inside the corresponding wiring frame.
- Do not ship the wireframe guide globe as the finished 3D world; it remains a real Three.js scene. Inspect applicable P2 styling while preserving the documented globe behavior.
- Reference viewport: 1920x1080. Top bar and timeline each have 20px outer insets and 60px height. The overview globe safe area is 700x700 at x=610,y=190. Latest activity is 480x128 at x=60,y=852.
- The app has one persistent globe and at most one expanded surface. The globe keeps its size and shifts sideways when a side surface opens.
- The feed is collapsed by default. The entire Latest activity card opens the 480x880 Activity panel at x=60,y=100.
- Clicking a creature or feed row opens the same left, map-linked popup, 480x429 at x=60,y=325.5. Keep the selected creature visible.
- Replay, Details and Dossier are buttons leading to same-size popup subviews. Back returns to the creature overview. Closing inspection restores its entry context.
- LIVE appears beside Timeline, not in the top bar. Keep the four counters centered in the top bar.
- Treat dimensions as desktop reference anchors. Use responsive layout and camera safe areas rather than scaling the whole application as one screenshot.

Data and state boundaries
- Define types from the documented event, session, attacker and stats contracts; retain their field names.
- Record the later integration configuration: NEXT_PUBLIC_API_URL=https://api.<domain> and NEXT_PUBLIC_WS_URL=wss://api.<domain>/live. Use NEXT_PUBLIC_MOCK=1 during M0-M4. In M5 connect the real backend and switch the default to NEXT_PUBLIC_MOCK=0 (compare explicitly; the string 0 is truthy in JavaScript). Supply .env.example with these public values and phase-specific usage instructions.
- Build a deterministic mock adapter and a clearly labeled data-mode control using the same types, including repeat visits, overlapping sessions, all kinds, an elite and a dragon. Mock is the active development mode through M4; keep Live unavailable until M5 implements it. After integration, isolate/reset mode-specific state and close the previous adapter when switching.
- Immediately after WebSocket JSON parsing, return when message.type === "ping". It arrives every 20 seconds with no session_id, geo or attacker. Never pass it to the attack reducer or create a creature/counter entry for it.
- GET /sessions/{id} returns {"session": {...}, "events": [...]}. Use response.session for session metadata and response.events for replay; never treat the response object as a plain event array.
- The teammate reports CORS allows localhost:3000, *.vercel.app and followthebreadcrumbs.tech. In M5 check /health, /stats and /sessions?limit=5 on the API host and verify actual browser fetches, then replay one returned session ID. Before then, exercise those shapes using fixtures. Report failures honestly while continuing to verify with labeled fixtures.
- Real sessions may be only brief bot knocks with no commands. The backend owner is fixing bots labeled as shadows. Render the received classification; do not force unknown traffic into golems.
- Creature names: Clay golem/Stone golem (bot), Dark mage/Evil witch (human), Fae/Cursed fae (agent). Slime, shadow, dragon and kind colors remain as specified. Latest handoff names override Mage/Witch abbreviations in wiring.
- One creature per attacker.ip_hash; sessions are visits. Keep selected attacker and selected session separate.
- Use a shared typed adapter interface for both real REST/WebSocket and mock data; presentation must not depend on which adapter is active.
- Keep domain state separate from surface, subview, selection, camera and return state. Keep the canvas mounted during interface navigation.
- Raw IPs, real passwords and secrets never reach the UI. Internal hashes are used for grouping and never displayed. Show city/country rather than coordinates.
- The browser does not send commands to the trap.

Milestone 1 - live experience with mock data
Implement /live with:
1. A working 3D globe, dotted land, atmosphere, fortress marker, orbit controls and colored attacker markers/arcs. Use simple explicit geometry for creature placeholders during this slice; detailed models come later.
2. Top bar, four counters, Timeline with LIVE, and Latest activity matching the layout.
3. Expand/collapse Live Feed; select a row or globe marker to focus a creature.
4. Creature overview and functional Replay, Details and Dossier subviews backed by fixtures, including correct close/back behavior.
5. Contract-shaped typed mock adapter and Zustand state supporting the flow above, with the real adapter interface reserved for M5.
6. The exact footer disclosure: "This is a research honeypot built for HackTX 2026. Connection data is anonymized and deleted after the event." Integrate it unobtrusively without obscuring the timeline.

The remaining website pages, full Event Log, Creature Key, hidden-controls zoom and real backend integration belong to later milestones. Any control outside this pass must be honestly marked unavailable rather than pretending to work. Do not add extra product features to fill space.

Definition of done
- Run the app locally and verify the entire overview -> Activity -> creature -> Replay/Details/Dossier -> back/close flow in the browser.
- Compare screenshots at 1920x1080 with the corresponding Figma frames. Check panel bounds, globe size/shift, typography hierarchy and absence of competing expanded panels. Compare structure against wiring and visual styling against Medieval Text-Book / P2 Blue-Gold separately. Correct geometry drift and styling mismatches before finishing; the old dark palette is not the target.
- Check a smaller desktop viewport for clipping and keyboard focus/return behavior. Respect reduced motion.
- Run the project's typecheck, lint and production build where available. Add focused tests for attacker grouping, event deduplication and navigation state if the necessary test setup exists or is warranted.
- Exercise mock transport fixtures so repeated ping messages do not mutate attack state and a wrapped {session, events} replay response renders events. Also verify a valid session with no command events shows an honest empty replay state.
- Fix in-scope failures and browser console errors before finishing. Do not claim a check passed if it could not run.
- Finish with what was implemented, the run command/local URL, verification performed, screenshots or their paths, and concrete remaining gaps. Update a short docs/frontend-progress.md checklist so the next pass can resume without rediscovery.

Start by inspecting the repository and relevant Figma frames, briefly state your implementation sequence, then build, verify and deliver M0 and M1 with their separate commits, pushes and PRs. Make routine implementation decisions and continue. Ask only if a missing design or contract decision prevents a correct implementation.
```

## Milestone 2 - full interface behavior

```text
Follow the milestone Git workflow in docs/frontend-implementation-prompt.md: verify this milestone, update progress, make a dedicated commit, push its feature branch and create its own correctly based PR. Preserve dependencies; do not merge or deploy. In every screen, use wiring for layout and interactions, and Stylization > Medieval Text-Book > P2 Blue-Gold (177:541; frames 177:542, 177:580, 177:781) for styling. Apply P2 styling within wiring geometry; wiring wins any structural conflict.

Continue Breadcrumbs from docs/frontend-progress.md using docs/frontend-spec.md and docs/architecture.md. Inspect the existing implementation first and keep its working behavior.

Use Figma MCP design context, screenshots and prototype wiring for Creature Key 120:8771, Event Log states under section 120:10051, event-list-origin inspection 160:496, hidden controls 120:10003, and zoom states under section 120:12009. Discover exact child frames before reading them.

Implement Creature Key; Event Log with four metrics, four sort choices, row/payload selection, pause/continue and return-to-list context; Hide Controls with background-click restoration and 1x-10x zoom. Pause freezes the displayed log while ingestion and the world continue. Opening Event Log overlays the current globe without moving the camera. Preserve one expanded surface. Keep the sound button hidden in the primary overview unless I explicitly approve its placement.

Keep mock mode active and use deterministic fixtures to exercise navigation, pause and creature variants with events arriving. Real backend connection is deferred to M5. Compare the requested states in the browser at the design viewport, run appropriate checks, fix in-scope issues, and update the progress checklist. Finish this pass as working code.
```

## Milestone 3 - website pages

```text
Follow the milestone Git workflow in docs/frontend-implementation-prompt.md: verify this milestone, update progress, make a dedicated commit, push its feature branch and create its own correctly based PR. Preserve dependencies; do not merge or deploy. In every screen, use wiring for layout and interactions, and Stylization > Medieval Text-Book > P2 Blue-Gold (177:541; frames 177:542, 177:580, 177:781) for styling. Apply P2 styling within wiring geometry; wiring wins any structural conflict.

Continue Breadcrumbs. Read the specs and progress checklist, then use Figma MCP context/screenshots for Home 120:11931, About 120:11955, Privacy 120:11982, and shared footer 120:12008.

Implement /, /about and /privacy with shared website structure. Get Started opens /live. Preserve the landing page's globe-left, content-right composition and scrollable footer. Keep the live canvas lifecycle independent from informational pages. Adapt the layout for narrow screens without claiming those adaptations are Figma-designed.

Use Breadcrumbs and the confirmed tagline every attacker leaves a trail. Include the exact shared footer disclosure: "This is a research honeypot built for HackTX 2026. Connection data is anonymized and deleted after the event."

The Privacy frame contains placeholder instructions. Use only confirmed project practices from the spec, clearly flag unresolved policy details in the development output, and do not invent a contact address, retention execution status, Source Code URL or Devpost URL. Keep unavailable links honest.

Verify page navigation, scrolling, footer and responsive layout in the browser; compare desktop screenshots and run appropriate checks. Update the progress checklist.
```

## Milestone 4 - world assets and frontend polish

```text
Follow the milestone Git workflow in docs/frontend-implementation-prompt.md: verify this milestone, update progress, make a dedicated commit, push its feature branch and create its own correctly based PR. Preserve dependencies; do not merge or deploy. In every screen, use wiring for layout and interactions, and Stylization > Medieval Text-Book > P2 Blue-Gold (177:541; frames 177:542, 177:580, 177:781) for styling. Apply P2 styling within wiring geometry; wiring wins any structural conflict.

Polish the existing Breadcrumbs world against the updated specs while preserving the verified wiring layouts. Replace explicitly temporary creature geometry with licensed local GLB assets for Clay golem/Stone golem, Dark mage/Evil witch, Fae/Cursed fae, kind-tinted slimes, shadow and dragon. Keep provenance/license information with the assets.

Implement the documented event animations, repeated-visit pulse, level of detail and bounded rendering. Check that asset sizes and visual effects do not obscure evidence panels or degrade interaction. Profile representative traffic on the available machine and report measured performance rather than promising 60fps without measurement. Verify reduced motion and WebGL failure handling. Keep optional sound, Story UI and automatic kiosk tours out of this pass unless separately requested.

Keep mock mode active; finish and verify frontend development before M5 connects the backend. Run the application, compare the relevant desktop states, fix visual regressions, run appropriate checks and update the progress checklist.
```

## Milestone 5 - connect frontend and backend

```text
Follow the milestone Git workflow in docs/frontend-implementation-prompt.md: verify this milestone, update progress, make a dedicated commit, push its feature branch and create its own correctly based PR. Preserve dependencies; do not merge or deploy. In every screen, use wiring for layout and interactions, and Stylization > Medieval Text-Book > P2 Blue-Gold (177:541; frames 177:542, 177:580, 177:781) for styling. Apply P2 styling within wiring geometry; wiring wins any structural conflict.

Frontend milestones M0-M4 are complete and verified. Now connect the developed Breadcrumbs frontend to the existing backend using its read-only FastAPI REST and WebSocket interfaces. Inspect the implemented types, adapters, reducer, CLAUDE.md and contracts/ before changing anything. Keep all field names and UI behavior intact.

Implement /attackers?limit=100, /sessions?limit=50, /stats and /sessions/{id}, plus /live WebSocket using NEXT_PUBLIC_API_URL and NEXT_PUBLIC_WS_URL. Validate incoming data, ignore ping, deduplicate event_id, buffer events during hydration, reconcile reconnect snapshots, and retain latest classified attacker kind and aggregate maximum threat. Multiple active visits must remain one creature. Stats count wild only.

Verify ping is discarded before attack validation and replay unwraps {session, events}. Use https://api.<domain> and wss://api.<domain>/live with mock off by default. Check sparse/short sessions, initial snapshots, browser CORS and mode switching without assuming that every session contains commands.

Retain explicit mock mode with the same interfaces and separate source tags. Do not silently substitute mock data on a failed live connection. Implement honest disconnected, empty and per-panel error/retry states. Keep sensitive values out of the browser and redact internal hashes/coordinates from displayed diagnostics.

Verify against fixtures first, then the configured backend when available. Report any contract mismatch rather than fabricating endpoints or successful integration. Run focused data tests and the project checks, and update the progress checklist.
```

## Manual setup reference (PowerShell)

For a fresh parent directory with no existing checkout:

```powershell
git clone https://github.com/aryansvt/hacktx2026.git
cd hacktx2026
git checkout -b world
npx create-next-app@latest world
```

Select TypeScript and App Router. The application lives entirely inside world/; project docs may live in docs/. If world or world/ already exists, reuse it instead of recreating it. The milestone workflow above uses feature branches and PRs targeting world (or their unmerged predecessor), rather than pushing every milestone directly into the integration branch.

A typical milestone commit/push after reviewing and staging only its intended files:

```powershell
git add world docs/frontend-progress.md
git commit -m "feat(world): complete milestone 1 live core"
git push -u origin codex/world-m1-live-core
gh pr create --base codex/world-m0-scaffold --head codex/world-m1-live-core --title "Frontend milestone 1: live core" --body-file milestone-pr.md
```

This example assumes M1 is the checked-out branch and M0 is still unmerged. If M0 is merged into world, use world as the PR base instead. Write the real PR description to milestone-pr.md before running the command. Use the appropriate branch and message for each milestone.

## How to refine this prompt

After the first build, give targeted corrections with a frame, element and expected outcome: "In 120:8573, keep the globe at its overview diameter and move it right; the current implementation shrinks it." Ask for the same browser checks after the fix. Update the spec if the correction changes intended behavior, so future passes keep it.

## Deployment handoff prompt - use when ready to deploy

```text
Prepare the completed Breadcrumbs frontend for Vercel. Inspect the actual app directory and set Root Directory to that folder (world or frontend). Configure NEXT_PUBLIC_API_URL=https://api.<domain> and NEXT_PUBLIC_WS_URL=wss://api.<domain>/live. Keep mock mode off for production and preserve the explicit testing/demo toggle.

Run the production build and verify the live integration, ping guard, wrapped replay response, required disclosure footer and branding. Report any unresolved failures before claiming readiness. When deployment is authorized, deploy and add followthebreadcrumbs.tech under Domains. Return the exact DNS record Vercel shows so I can pass it to the teammate who manages DNS. Do not invent DNS values or contact the teammate on my behalf. If deployment access is unavailable, complete local preparation and give me the precise remaining dashboard steps.
```

Prompt structure reference: [OpenAI Codex best practices](https://learn.chatgpt.com/docs/learn/best-practices). The guidance supports supplying task context, constraints and clear completion criteria; the project-specific phases and design decisions above come from the supplied specs and inspected Figma wiring.
