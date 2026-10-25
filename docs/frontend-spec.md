# Breadcrumbs | Frontend specification
Revision 4 - October 25, 2026 - wiring layout with P2 styling

Confirmed identity: Breadcrumbs. Tagline: every attacker leaves a trail. Public site: https://followthebreadcrumbs.tech. The latest user-supplied backend handoff overrides older naming and branding in the wireframes.

Delivery update: develop the frontend inside world/ using contract-shaped mock data through milestones M0-M4. Connect the existing backend only in M5; live-default requirements below describe the integrated result. Each milestone requires verification, a dedicated commit, a push and its own PR. Follow docs/frontend-implementation-prompt.md for branch dependencies and exact milestone scope. The repository is https://github.com/aryansvt/hacktx2026.git; world is the requested frontend integration branch.

## 1. Scope and source of truth
This revision replaces the screen layout and navigation in the supplied 15-page Frontend Spec. It follows hacktx2026 > wiring in Figma, inspected October 25, 2026. Existing data, privacy, attacker grouping, and rendering requirements are retained unless explicitly changed below. Figma example metrics and event text are illustrative, not production values.

Design: https://www.figma.com/design/XJrA0l8ncO2HAKQqUouFo2/hacktx2026?node-id=120-6497

The wiring page controls page structure, proportions, component placement, panel sizes, safe areas and interactions. The selected visual styling comes from hacktx2026 > Stylization (173:869) > Medieval Text-Book (177:540) > P2 Blue-Gold (177:541): Landing 177:542, Overview 177:580, Live event log 177:781. Apply that styling as closely as possible inside wiring's layout. Wiring takes precedence in structural conflicts; the styling frames supply typography, colors, surfaces, borders, accents and decoration. Use the exact Medieval Text-Book variant, not Medieval Modern or Storybook. This selection supersedes the original dark-theme-only requirement. The globe remains a working 3D scene, not the guide-circle placeholder.

Styling reference: https://www.figma.com/design/XJrA0l8ncO2HAKQqUouFo2/hacktx2026?node-id=177-541

### What changed
- Public entry is now a landing page with Get Started; the live experience remains directly accessible.
- Default live view uses a compact Latest activity card, not an always-open feed rail.
- The globe keeps its size and moves horizontally to make room for an expanded surface.
- Creature inspection is a left, map-linked popup. Replay, Details, and Dossier are separate views reached by buttons, not right-rail tabs.
- LIVE belongs beside Timeline. View Event Log is on the timeline's right edge.
- Event Log replaces the old user-facing Under the hood label and adds sorting, pause, payload selection, and return navigation.
- Hide Controls is a reversible presentation state with explicit zoom controls; it does not imply an automatic kiosk tour.
- Add Creature Key, About, Privacy Policy, and shared website footer.

### Evidence precedence
Use actual standalone wiring frames over stale planning annotations. The popup is 480 x 429 in the inspection frames; the planning text's 450 x 405 is outdated. Use Event Log as the visible title in the wired states; Live diagnostics describes its purpose and remains in an earlier planning board.

## 2. Website pages and navigation
Route names below are implementation proposals; Figma specifies destinations rather than URL paths.

| Page / proposed route | Required layout and behavior |
| --- | --- |
| Home / | Brand at top left; short cybersecurity descriptor at right. Large globe-led hero on the left; FOLLOW THE TRAIL, Breadcrumbs, Meet the creatures at the gate, explanatory paragraph, and Get Started on the right. CTA enters live overview. |
| Live /live | Full viewport world with top bar, compact activity entry, timeline, and mutually exclusive expanded surfaces. |
| About /about | Back to Home; project introduction; Live globe, Creature cards, and Event log feature descriptions; team attribution; Get Started. |
| Privacy /privacy | Back to Home; sections for collection, uses, retention, third parties, and contact. Figma supplies layout and placeholder prompts only. Publish confirmed project practices, not placeholder prose. |

The Home, About, and Privacy frames are 1920 x 1080 viewports containing 1576px-tall scrollable content. Their footer includes Breadcrumbs, the confirmed tagline every attacker leaves a trail, About, Privacy Policy, Source Code, Devpost, copyright 2026, and Built by Wizards of Claude. Source Code and Devpost destination URLs remain to be supplied; do not invent them. Preserve layout while updating superseded brand copy.

Preserve existing #live deep links by directing them to the live experience. Legacy #guest and #kiosk are retained requirements outside this desktop wiring's acceptance scope; they must not silently acquire new behavior from Hide Controls.

## 3. Live overview and geometry
The reference viewport is 1920 x 1080. Measurements below are design anchors, not rigid dimensions for every device. Keep the globe and selected creature visible, and prevent surfaces from overlapping the top bar or timeline.

| Region | Reference bounds x, y, width, height | Contents |
| --- | --- | --- |
| Top bar | 20, 20, 1880, 60 | Breadcrumbs left; Attacks, Active, Countries, Breaches centered; Hide Controls and Creature Key right. |
| Overview globe safe area | 610, 190, 700, 700 | Globe, fortress, travel paths and creatures. |
| Latest activity | 60, 852, 480, 128 | Latest event summary, city and age, Click to view all activity. Entire card is clickable. |
| Exploration hint | Beneath globe, y=906 | Drag to explore; click a creature to inspect. |
| Timeline | 20, 1000, 1880, 60 | Timeline, LIVE, bars/ticks, Now, View Event Log. |

Attacks is total wild sessions, not unique attackers. Active and Countries come from backend stats; Breaches means simulated successful entries to the honeypot. Never imply compromise of a real protected system. On disconnection, replace LIVE with a nonblocking reconnecting state. Bootstrap recent history without fabricating active attacks.

The single-expanded-surface rule governs Activity, Creature Key, creature popup, and Event Log. Opening one suspends or closes the other expanded surface. Retain enough return state to restore the previous view. Compact background elements may remain where the frame explicitly shows them, such as Latest activity behind Creature Key.

### Timeline
Retain the last-24-hours attack history, colored by kind. Wiring uses thin 8px bars, 48 ticks spanning the first through last bar, and only Now beneath the final tick. Reveal times and counts on hover or keyboard focus. Aggregate minute samples to the available display width; tick count does not redefine the backend's minute resolution. View Event Log remains visible while the log is expanded.

## 4. Activity and creature inspection
### Activity pullout
Click Latest activity to open Live Feed at 60,100 with size 480 x 880. It replaces the compact card. The globe remains 700 x 700 and shifts right to 862,190. Show newest-first event rows with creature, city, action, relative time, and family where available. Retain the last approximately 100 events in a bounded list. X returns to overview. Keep filters inside this surface, with Filter Activity as its accessible label; the exact filter menu is not fully specified by the inspected frames.

Retain kind, harmless, and team-traffic filters from the original spec. Team traffic defaults on with a simulated tag, but never enters wild stats. A filter affects presentation, not event ingestion or authoritative totals.

### Shared creature popup
Selecting a map creature or feed row focuses the creature, collapses Activity, and opens the same map-linked popup at 60,325.5 with size 480 x 429. The globe shifts to 847,190 for direct inspection or 862,190 in the event-list-origin frames. Draw an anchor to the selected creature and keep it unobscured.

Overview contains creature title and preview; kind, variant, threat; reputation and family; confidence and reason chips; city/country; SSH client when applicable; duration and command count. Bottom actions are Replay, Details, Dossier. No Story tab is present in wiring.

| View | Required content and return |
| --- | --- |
| Replay | Timestamped connection, command, reply, and ending sequence for the selected session. Top-right back arrow returns to the creature overview. |
| Details | Readable explanation of classification, reputation, confidence, threat, evidence, location, client, duration, and command count. Back returns to overview. |
| Dossier | Structured identity, reputation, family, confidence, session facts and evidence. Retain backend reputation summary and clickable sources when available. Back returns to overview. |

All subviews keep the overview popup's dimensions and vertical center; long content scrolls inside. Back arrows have accessible names but no visual tooltip, matching wiring. Direct inspection uses a close control; event-list-origin inspection uses Back to Event List and restores its source list. Preserve sort, pause, scroll, selected event, and camera context across the return. The prototype's direct-close destination is Activity; use that as the default return, with prior context when one exists.

Original timed terminal replay and 1x/2x/4x controls are not drawn in the new replay frame. Treat them as retained optional enhancements, not required new chrome. Backend story events remain supported, but story presentation is deferred pending a designed destination. Do not relabel Details as Story.

## 5. Creature Key, display and diagnostics
### Creature Key
Book icon opens a right-side key at 1386,218, size 474 x 644; globe shifts left to 361,190. X dismisses it. Explain kind as behavior, variant as reputation and threat, family as known group/tool, and gold fortress as the honeypot destination. Labels must carry meaning without color alone.

| Kind | Unknown reputation | Malicious reputation | Harmless |
| --- | --- | --- | --- |
| bot | Clay golem | Stone golem | Green-tinted slime |
| human | Dark mage | Evil witch | Blue-tinted slime |
| agent | Fae | Cursed fae | Purple-tinted slime |
| unknown | Shadow until classified | Shadow until classified | Shadow until classified |

Critical threat takes precedence and renders a dragon. The latest backend handoff confirms Clay golem/Stone golem, Dark mage/Evil witch, and Fae/Cursed fae. Use these full names even where wiring abbreviates Mage/Witch; robot/orc/alien are retired. Wire values remain bot, human, agent, unknown; variant values remain slime, base, elite, dragon. Shadow is an unclassified rendering state.

### Hide Controls and zoom
Hide Controls hides the normal top bar, timeline and panels. Show Click anywhere to show controls, a fixed circular globe viewport at 600,132 sized 720 x 720, and centered zoom controls at 756,896 sized 408 x 58. Zoom changes contents within this viewport. Buttons step 1x, 1.5x, 2.3x, 3.4x, 5.1x, 7.6x, 10x; scroll/pinch is continuous and clamped to 1x-10x. Zoom-control clicks must not bubble into restore-controls behavior. A background click restores the prior interface; do not mistake an orbit drag for a click.

Sound On/Off states exist, but the sound button is hidden in the principal overview frames. Keep audio off by default. Treat visible sound control placement as unresolved optional UI; when enabled, use Turn Sound On / Mute Sound labels and retain the state through navigation. Do not add an always-visible button contrary to the reference overview.

### Event Log
View Event Log opens a bottom overlay at 20,520, size 1880 x 470. Keep the globe's existing size and camera position behind it. Close reveals the previous view. The overlay has a title/subtitle, Pause/Continue Stream, close control, and four metrics: Events per Second, Avg Response - Engine, Avg Response - LLM, Latest Event.

Below the metrics, left side is Event Stream with Time, Event, Creature / Session; right side is selected event identity, classification reason chips, and sanitized JSON. Selecting a row inspects its payload; opening its creature uses the separate event-list-origin popup flow. Sort options: Newest First, Oldest First, Event Type, Creature. Use timestamp and event ID as stable tie breakers.

Pause freezes visible rows and the selected payload only. Keep receiving events and updating world state; Continue Stream catches the list up to the bounded current buffer. Proposed metric window is the last 60 seconds of received events; label it and do not imply backend-wide totals. Mean response time uses command events with finite response_ms grouped by answered_by. Empty groups show no data, not zero. Cache timing remains available in payload/details without adding a fifth metric to the designed strip.

## 6. World behavior and data contracts
Retain dotted dark continents, atmosphere, restrained stars, gold fortress and gate ring. Use the deployed trap region for the fortress; Dallas remains a fallback pending confirmation. Travel follows great-circle arcs; bots approximately 4 seconds, humans/agents approximately 8 seconds. Orbit damping and zoom limits apply. Auto-rotate about once per 90 seconds, pausing on interaction. Map creatures to colored dots at distance and models nearby.

One creature represents one attacker.ip_hash, with session histories underneath. First visit spawns; repeated visits pulse the existing creature, increment its visit count and optionally scale it up to 1.6x. Preserve most recent classified kind across new unknown sessions. Use max_threat across visits for aggregate aura and critical dragon override; show selected-session threat separately in cards. A session ending must not dissolve a creature with another active visit.

| Event | World / UI effect |
| --- | --- |
| session_start | Spawn unknown origin ripple or pulse an existing attacker; start travel. |
| login_fail / login_success | Gate bounce and spark / entry flash and move inside. |
| command | Technique glyph; append command and fake reply to session record. HTTP requests use the same event form. |
| tripwire | Purple flash; update evidence. Reveal Fae only when classification supports agent. |
| classified | Morph to resolved kind and variant; update confidence and reasons. |
| dossier / story | Update stored enrichment; dossier available in popup; story has no required new UI. |
| session_end | End this visit; dissolve aggregate creature only when no visits remain active; retain history. |
| critical threat | Dragon override, fortress pulse; optional camera emphasis outside active user inspection. |

### API and transport retained
| Interface | Purpose |
| --- | --- |
| GET /attackers?limit=100 | Startup aggregate attackers, visits, max_threat and session_ids. |
| GET /sessions?limit=50 | Recent session summaries and history bootstrap. |
| GET /stats | Counters and minute history on load and every 10 seconds. |
| WS /live | Live JSON events; ignore type=ping keepalives with no session_id. |
| GET /sessions/{id} | Object containing session summary and ordered events for inspection/replay. |

Read base URLs from NEXT_PUBLIC_API_URL and NEXT_PUBLIC_WS_URL. The supplied spec lists https://api.followthebreadcrumbs.tech and wss://api.followthebreadcrumbs.tech/live; availability was not reverified for this documentation revision. Reconnect with 1,2,4 seconds, capped at 10. Reconcile snapshots and deduplicate by event_id; reconnect may require a history refresh because no resumable cursor contract is specified.

## 7. Backend handoff and deployment
The backend is maintained by another teammate. Read CLAUDE.md, contracts/, and any applicable repository instructions in the actual application repository before implementing types. The current workspace has no Git checkout or contracts to pull. In the real checkout, inspect branch and working-tree state, then integrate origin/main safely; do not run a blind pull that could overwrite work or invent a remote. Exact contracts take precedence over illustrative examples here. Report actual mismatches instead of changing backend field names.

Live configuration: NEXT_PUBLIC_API_URL=https://api.followthebreadcrumbs.tech; NEXT_PUBLIC_WS_URL=wss://api.followthebreadcrumbs.tech/live; NEXT_PUBLIC_MOCK=0. Parse the mock flag explicitly (the string 0 must not enable it). Default to live; keep a clearly labeled Mock/Live toggle for sparse real traffic and demos. Changing mode resets or isolates buffers, histories and counters and closes the old adapter.

Handle WebSocket {"type":"ping"} every 20 seconds immediately after parsing JSON, before attack-event validation, reducer calls, counters or creature creation. It has no session_id, geo or attacker. GET /sessions/{id} returns {"session": {...}, "events": [...]}; hydrate the summary from session and replay from events. Never treat the whole object as an event array. Add regression coverage for both shapes.

Teammate-reported CORS allowlist: localhost:3000, *.vercel.app and followthebreadcrumbs.tech. Smoke-check /health, /stats and /sessions?limit=5 on the API host; then use a returned session_id to check replay. A successful server-side fetch does not prove browser CORS. Real traffic is sparse and mostly short bot login attempts; an empty command replay can be valid. A backend classification fix is pending for bots appearing as shadows. Do not locally reclassify unknown traffic as bots just to populate golems.

Vercel handoff: Root Directory is the actual app folder (world or frontend). Add the two public API env vars and leave mock mode off. Add followthebreadcrumbs.tech under Domains. Capture the exact DNS record Vercel provides and return it to the user for the teammate who manages DNS; do not guess record values. These are deployment instructions, not evidence that deployment or DNS changes have been performed.

## 8. Schemas, implementation and acceptance
### Contract field reference
Event envelope: event_id, session_id, type, timestamp, source, protocol, geo, attacker, detail. source is wild/guest/team/mock; protocol includes ssh/http. geo has lat, lon, country, city. attacker carries kind, confidence, reputation, family, threat, client, ip_hash. threat wire value med is displayed as medium. Each event carries latest known attacker values; merge into the session while preserving attacker-level latest classified kind and maximum threat.

detail by type: session_start has optional guest_name; login events have username; command has command, output (up to 500 characters), response_ms, answered_by (engine/llm/cache), techniques; tripwire has tripwire_id and reasons; classified has reasons; dossier has summary and sources[{title,url}]; story has story; session_end has duration_s and command_count.

Session summary: session_id, started_at, ended_at, source, geo, attacker, status, login_fails, command_count, story. status is approaching/at_gate/inside/ended. Attacker summary: ip_hash, visits, first_seen, last_seen, latest_session_id, source, geo, attacker, max_threat, session_ids. Stats: total_sessions, active_now, countries, breaches, by_kind, by_reputation, per_minute[{t,bot,human,agent}]. All stats count wild only. Add unknown buckets only if supplied by the backend; do not invent missing totals.

Use Next.js App Router and TypeScript in world/, react-three-fiber/drei, Zustand, and short panel motion. Keep sessionsById, attackersByHash, bounded events, authoritative stats, selection, surface/return context, camera, zoom and diagnostics pause state separate. A single event reducer feeds all read-only views; inspection never sends commands to the trap. Fetch failures stay local to the panel with retry; do not blank the globe. Missing evidence, location or dossier content is shown as unavailable, not generated by the browser.

The selected frames use parchment backgrounds (frame fill #efe3c8), Pirata One, EB Garamond and Inter, with blue/gold treatments. Extract exact role-specific styles from Figma during implementation. Map those styles into shared tokens and components; do not stretch the whole page, move panels, or replace wiring geometry to accommodate decorative treatments. States without a styling equivalent inherit these tokens within their own wiring structure. Verify layout against wiring and styling against P2 as separate checks.

Use Medieval Text-Book / P2 Blue-Gold for production interface styling, replacing the original dark background/panel palette and generic type suggestions. Preserve semantic creature kind colors (bot #7ec46a, human #6fa8dc, agent #b48ce0, unknown #8a9490, critical #e5574a) and readable labels unless a later explicit design decision changes them. Map the selected Figma fonts to their actual roles, preserve data legibility, and keep the globe behavior and wiring geometry intact. Target 60fps, instancing, roughly 300 active rendered creatures, and compressed GLB assets under about 10MB total. Asset licenses must be checked during implementation.

### Privacy and safety retained
Attacker commands never execute. Raw IPs, actual passwords, and secrets never reach any browser surface, including JSON. Hashes are internal grouping keys and must also be removed from displayed JSON. Round locations to city-level precision (at most two decimals), add display jitter, and show city/country only. Guest/team origins are Austin and visibly tagged; guests have gold outlines and optional names. Source URLs and command text must be sanitized against accidental sensitive disclosure. Data is scheduled for deletion after the event; deletion execution and the final policy need operator confirmation. No downloadable IP/location lists.

Include the exact required footer: "This is a research honeypot built for HackTX 2026. Connection data is anonymized and deleted after the event." Put it in the shared website footer and provide an unobtrusive live-view disclosure. Exact live placement is not drawn in wiring and needs layout integration. Do not copy placeholder policy prompts into a public policy.

## 9. Responsive behavior and acceptance
Wiring defines desktop only. Retain the prior mobile fallback as provisional: globe above the feed, creature inspection as a bottom sheet, desktop-only kiosk/guest. Adapt large diagnostics into a list/detail flow; mobile geometry is not Figma-verified. All controls need keyboard access, visible focus, labels and sensible return focus. Provide Escape dismissal, reduced-motion camera behavior, textual equivalents to creature colors, and nonblocking loading/empty/disconnected states.

Mock mode uses NEXT_PUBLIC_MOCK=1 or ?mock with the same contracts and explicit mock source. Retain weighted cities, repeated attackers, login/command/tripwire/escalation cases and stored replay history. Never mix mock totals with live wild totals. Legacy guest flow still uses an external terminal, optional name, backend-provided guest identity, highlighted creature and source separation; guest provisioning contract remains outside the supplied API list. Automatic kiosk touring and story presentation are follow-up scope.

### Acceptance checklist
- Get Started opens overview; About, Privacy and footer links resolve appropriately.
- Latest activity opens the feed; row selection focuses the same creature without a second expanded panel.
- Replay, Details and Dossier retain popup size; all back/close paths restore the correct origin.
- Creature Key uses golem/mage/fae names and explains critical precedence.
- Event Log preserves camera position, supports four sorts and freezes rows without pausing ingestion.
- Hide Controls restores state, zoom clamps to 1x-10x, and zoom buttons do not restore controls accidentally.
- Repeat visitors stay one creature; overlapping visits do not cause premature removal.
- Wild stats exclude team/guest/mock; displayed payloads contain no raw IP, hash, coordinates, or passwords.
- Confirm privacy copy/contact, external footer URLs, sound placement and optional story/replay controls before claiming those features complete.

Reference nodes: overview 120:8390; activity 120:8573; key 120:8771; inspection 120:9037/120:9236/120:9421/168:522; event-list inspection 160:496; Event Log 120:10052-120:11427; hidden controls 120:10003; zoom 120:12009; Home 120:11931; About 120:11955; Privacy 120:11982; footer 120:12008. These identifiers are Figma node IDs, not numeric ranges for iteration.
