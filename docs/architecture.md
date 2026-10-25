# Breadcrumbs | Architecture
Revision 4 - October 25, 2026 - wiring layout with P2 styling

Product: Breadcrumbs. Tagline: every attacker leaves a trail. Public domain: followthebreadcrumbs.tech. Latest backend handoff naming overrides abbreviated wireframe labels.

Delivery update: scaffold and build world/ in milestones M0-M4 using mocks that follow contracts/. M5 connects the finished frontend to the teammate's existing backend. Live-default behavior below applies after integration. Every milestone ends with verification, a dedicated commit, a pushed branch and its own PR; do not merge or deploy automatically. See docs/frontend-implementation-prompt.md for the milestone plan and stacked-PR workflow targeting the requested world integration branch in https://github.com/aryansvt/hacktx2026.git.

## 1. System purpose and revision scope
An isolated honeypot receives SSH and HTTP traffic. A fake shell sustains the interaction without executing attacker commands. Classification and reputation enrichment turn behavior into typed events. The backend stores history and broadcasts sanitized data. Breadcrumbs renders each distinct attacker as a creature with multiple visits, then exposes the evidence through the Figma wiring layouts.

This revision reconciles the supplied architecture image and Ground rules image with the Frontend Spec and hacktx2026 > wiring. It describes intended architecture, not a deployment audit. The local workspace contained no implementation to verify. Existing production URLs are recorded from the source spec, not independently tested.

Figma source: https://www.figma.com/design/XJrA0l8ncO2HAKQqUouFo2/hacktx2026?node-id=120-6497

### End-to-end flow
1. Bot, human, agent, or tagged guest connects to the isolated trap over SSH :22 or HTTP :80.
2. The deterministic engine answers common fake-shell commands. An LLM answers other commands. Both operate on virtual filesystem state; neither invokes a host shell.
3. Connections, logins, commands and tripwires become raw events in Redis Streams.
4. The brain classifies behavior, performs approximate geo lookup, computes threat and technique mapping, and adds cached reputation/dossier/story enrichment using SerpApi and LLM calls.
5. The FastAPI backend persists sanitized session/event history in Tiger Data (Timescale Postgres), maintains attacker aggregates, and fans out events over WebSocket.
6. The world client hydrates snapshots, merges live events, derives creature appearance and renders the globe plus the selected interface surface.

The original trap-to-Redis drawing is a logical event path. Recommended deployment detail: send trap events through an authenticated private backend ingress that writes Redis, preserving the ground rule that trap egress is restricted to backend and LLM API. If Redis is contacted directly, it must be private backend infrastructure explicitly covered by the network allowlist; never expose its port publicly.

## 2. Components and trust boundaries
| Component | Stack retained | Responsibility |
| --- | --- | --- |
| Trap | Python, asyncssh, FastAPI, Claude Haiku | SSH server, fake HTTP pages, tripwires, fake-shell engine, virtual filesystem. |
| Brain | Python, MaxMind GeoLite2, SerpApi, LLM calls | Behavior classification, cached reputation, approximate geo, threat, techniques, dossier and story. |
| Backend | FastAPI, Redis Streams | Ingress, orchestration, session/attacker API, stats and WebSocket fan-out. |
| Storage | Tiger Data / Timescale Postgres | Ordered event history, sessions, attacker aggregates, continuous aggregates for stats. |
| World | Next.js, TypeScript, react-three-fiber, drei, Zustand | Website pages, globe, creatures, view state, inspection and Event Log. |
| Hosting | Vultr, Docker Compose, Vercel, .tech domain | Isolated trap and backend compute; web frontend hosting. |

Keep the trap and backend on separate trust boundaries. The orange exposed trap is the only intentionally attack-facing workload; the public read API and website are also internet-accessible but must not expose Redis, database, administrative services, or trap control. The original caption claiming only one component is internet-exposed was too broad for a public API/site architecture.

### Ground rules
- Attacker commands never run. Engine and LLM return text and mutate constrained virtual JSON state only.
- Trap holds no real secrets. Outbound connections are restricted to backend ingestion and the LLM API.
- Raw IPs and real passwords never reach the world. Use salted stable hashes internally for grouping; discard password values and retain only required outcomes/flags.
- Guest and team sessions are tagged and excluded from real attack statistics. Mock is also excluded.

The brain may need raw network indicators for geo/reputation lookup before anonymization. Keep those within a restricted processing boundary and minimize retention. SerpApi is an external recipient of queried indicators; the final privacy policy must accurately explain this. Do not claim that every stage operates solely on hashes.

All published event text and dossier/source content pass sanitization before delivery. The client adds a presentation redactor for Event Log so internal hashes and coordinate fields are not displayed. Render command output as inert text. Browser controls never become a terminal or administrative endpoint.

## 3. Frontend composition and navigation
Proposed routes are / (Home), /live, /about, /privacy. Figma defines navigation, not route names. Preserve legacy #live entry through a redirect/adapter. Guest and automatic kiosk modes remain separate legacy capabilities outside the inspected desktop wiring.

Design responsibilities are split deliberately: wiring (120:6497) owns page structure, component positions, proportions, safe areas and behavior; Stylization (173:869) > Medieval Text-Book > P2 Blue-Gold (177:541) owns visual styling. Read its Landing 177:542, Overview 177:580 and Live event log 177:781 frames. Implement their actual fonts, parchment surfaces, blue/gold accents and component treatments through shared tokens. Wiring wins structural conflicts. Extend P2 styling to states without a styled counterpart using the corresponding wiring layout. The original dark-theme-only requirement is superseded. Review layout fidelity and styling fidelity separately.

The live route has one persistent world canvas and an HTML interface layer. Keep the canvas mounted through feed, popup and diagnostics transitions; remounting would reset creatures, camera and animations.

| Client module | Owns |
| --- | --- |
| SiteShell / Footer | Landing, About, Privacy and website navigation. |
| LiveShell / TopBar | Brand, four wild stats, Hide Controls, Creature Key. |
| WorldCanvas / CameraController | Globe, fortress, attacker meshes, travel, safe-area shifts, zoom. |
| LatestActivity / ActivityPanel | Compact newest event entry and expandable feed/filter surface. |
| CreaturePopup | Overview and Replay/Details/Dossier subviews; origin-aware return. |
| CreatureKey | Behavior/variant legend and labels. |
| Timeline / EventLog | History strip, connection state, diagnostic list, sort/pause, payload evidence. |
| Transport / EventReducer | Snapshot fetching, live connection, validation, deduplication and merging. |
| MockAdapter | Same read interfaces and event schema with clearly labeled synthetic data. |

### UI state model
Keep route, controlsVisible, surface (none/activity/creature/key/eventLog), creatureView (overview/replay/details/dossier), selectedAttackerKey, selectedSessionId, selectedEventId and returnContext distinct. Camera state, zoom, sound state and diagnostics sort/pause are separate from data state. This is a proposed implementation model matching wiring, not a new backend contract.

Opening a surface replaces the previous expanded surface and stores return context. Creature selection collapses Activity and shifts the full-size globe right. Creature Key shifts it left. Event Log overlays the existing world without moving or resizing the camera. Hiding controls stores the interface state and presents the dedicated zoom composition; background click restores it. Zoom buttons consume their own input.

A creature opened from Event Log returns to its list, with selected event, scroll, sort and pause preserved. Nested creature subviews return to overview before leaving inspection. The diagram's old right-hand card and Story/Replay/Dossier tab arrangement is superseded by the left popup and Replay/Details/Dossier buttons.

## 4. Domain model and event processing
Store sessions by session_id, attackers by stable ip_hash, and events by event_id with bounded recent-event indices. A session is a visit; an attacker is the rendered creature. Attacker aggregation is essential because hundreds of visits can come from only a few sources.

Hydrate /attackers, /sessions and /stats, buffering live events during snapshot loading. Merge snapshots and buffered events using IDs and timestamps to avoid duplicates and older snapshots overwriting newer state. Exact server cursor/version semantics are not supplied; timestamp merging and refetch are a best-effort fallback, not a guarantee of gapless replay.

For every event: validate envelope, ignore transport ping, deduplicate event_id, merge session state, update attacker membership and aggregate metadata, append to bounded feed/diagnostics buffers, and issue an animation intent. Record session IDs as a set so duplicate session_start messages do not increment visits twice. Load full selected-session history through /sessions/{id} rather than relying on a truncated feed.

Use latest classified kind, not an unknown reconnect value, for the aggregate creature. Use aggregate max_threat for persistent aura and critical dragon override. Session cards show that session's latest threat and evidence. When one visit ends, remove only its active membership; an attacker with another active visit stays visible. Keep ended history even when an idle mesh is evicted.

### Creature projection
Priority: aggregate critical -> dragon; unknown kind -> shadow; harmless -> kind-tinted slime; malicious -> elite form; otherwise base form. Base/elite names: bot Clay golem/Stone golem; human Dark mage/Evil witch; agent Fae/Cursed fae. Kind colors and readable labels remain consistent across world, feed, key and popup. Robot/orc/alien labels from the old architecture image are retired. Sparse live traffic and short bot knocks are expected; a backend fix for bot/shadow classification is pending. Never infer bot solely from a short session on the client.

### Diagnostics is a read projection
Event Log reads sanitized client events and classifier evidence. Pause freezes its presentation snapshot, not the transport, store, stats, or globe. Proposed local metrics use a labeled 60-second window: arrival rate, mean engine latency, mean LLM latency and most recent event age. Cache timings remain inspectable. If global diagnostics are later required, add an explicit backend metrics contract; do not present local samples as server-wide measurements.

## 5. Interfaces, persistence and failure handling
| Endpoint / channel | Consumers and semantics |
| --- | --- |
| GET /attackers?limit=100 | Aggregate world bootstrap; visits, max_threat, latest classified attacker, session_ids. |
| GET /sessions?limit=50 | Recent sessions / fallback history. |
| GET /sessions/{id} | Selected session and ordered event history; Replay, Details, Dossier. |
| GET /stats | Authoritative wild-only totals and minute history; poll every 10 seconds. |
| WS /live | Event stream and ping every approximately 20 seconds; no command channel. |

Preserve the envelope and detail fields documented in the companion frontend specification. UI changes do not require renaming wire fields or adding endpoints. The original architecture screenshot's shorter event example is incomplete; retain event_id, timestamp, protocol, client and stable ip_hash from the full frontend contract. Internal ip_hash is never a visible label.

Store events with unique event IDs and timestamps, sessions with start/end and source, and attacker aggregates with visit membership, most recent classified kind and maximum threat. Index session event lookup and recent activity. Aggregate wild-only stats by time and classification. Database schema and migration syntax are implementation work; no current schema was available to verify.

Production bases recorded in the source: https://api.followthebreadcrumbs.tech and wss://api.followthebreadcrumbs.tech/live, configured by NEXT_PUBLIC_API_URL / NEXT_PUBLIC_WS_URL. Verify CORS and actual deployment settings during implementation; documentation alone is not evidence they remain configured.

Backend-owner handoff confirms the same URLs and reports CORS support for localhost:3000, *.vercel.app and followthebreadcrumbs.tech. Default the app to live with NEXT_PUBLIC_MOCK=0; compare that string explicitly. Preserve a labeled Mock/Live toggle and isolate adapters/state on mode changes. Backend code belongs to the teammate; use the actual repository's CLAUDE.md and contracts/ as integration references. Safely integrate origin/main in the real Git checkout after inspecting local changes. This documentation workspace has no Git checkout to update.

Transport guard: parse JSON, discard type=ping immediately, then validate and reduce attack events. Pings arrive every 20 seconds without session_id, geo or attacker. Replay adapter must unwrap {session, events}; do not cast the response to an event array. Regression checks must cover ping causing no state mutation and wrapped replay displaying events. Smoke checks are /health, /stats, /sessions?limit=5, then /sessions/{id} from a returned ID. Verify browser CORS separately.

On disconnect, keep existing scene and show reconnecting beside Timeline. Backoff 1,2,4 seconds capped at 10; refetch snapshots after reconnect. Deduplicate replayed events. A bad message must not crash rendering. If history fails, show a local retry state. If all data is unavailable, show an honest empty world/status; do not substitute fake attacks into a live feed without an explicit demo label.

Mock mode should be one adapter selected by NEXT_PUBLIC_MOCK=1 or ?mock. Prefer the original spec's in-browser generator; the architecture image's ws://localhost:8765 server is an optional development transport, not a production dependency. Both must use the same schema and keep source=mock separate from real stats.

## 6. Hosting handoff
Deploy the actual app folder as Vercel's Root Directory (world or frontend), set the two API environment variables, and keep mock mode off. Add followthebreadcrumbs.tech to the project Domains. Return Vercel's exact DNS record to the user for the teammate who owns DNS. No deployment or DNS change is implied by this document.

The shared website footer must include: "This is a research honeypot built for HackTX 2026. Connection data is anonymized and deleted after the event." Include the disclosure unobtrusively in the live experience as specified in the frontend document.

## 7. Delivery boundaries and verification
### Implementation sequence
1. Site routes, shared footer, live shell and interface state machine matching wiring.
2. Transport/mock adapter, normalized stores, deduplication and attacker aggregation.
3. Persistent globe, safe-area camera shifts, Latest activity and Live Feed.
4. Creature popup and nested Replay/Details/Dossier flows, including event-list return.
5. Timeline, Event Log, stable sorting, pause and display redaction.
6. Creature Key, Hide Controls, bounded zoom, accessibility and performance.
7. Confirm policy/external links; integrate optional sound, richer replay and legacy guest/kiosk separately.

### Verification requirements
- Contract fixtures cover all event types, HTTP commands, ping, missing enrichment, out-of-order arrivals and duplicates.
- Multiple overlapping sessions per hash produce one creature and accurate visits; ending one session leaves other active visits visible.
- Reconnect/snapshot merge does not duplicate feed rows or roll back classification.
- Stats remain wild-only while filters and diagnostics pause change presentation.
- Back navigation restores prior surface and diagnostics state; one expanded surface remains active.
- Displayed JSON, source labels and command text reveal no raw IP, password, internal hash or precise coordinates.
- Camera stays full-size behind Event Log, shifts for side surfaces, and hidden-mode zoom remains within 1x-10x.
- Operator verifies trap isolation, no execution paths, egress allowlist, persistence retention and deletion after the event.

### Explicit open decisions
The Privacy frame is a placeholder. Confirm data handling, third-party disclosures, retention execution and contact before publishing. Supply Source Code and Devpost URLs. Main wiring hides the sound button despite sound-state frames; decide placement before enabling it. Story events remain in the model without a designed destination. Desktop layouts are verified against wiring; mobile and guest provisioning need separate design/API confirmation. Replay speed controls and automatic kiosk tours are retained optional legacy scope, not proven by these frames.

### Source record
Frontend basis: hacktx2026 Frontend Spec-1.pdf, supplied by user (15 pages). Architecture basis: supplied How an attack becomes a monster screenshot and Ground rules screenshot. Layout and interaction authority: hacktx2026 Figma wiring page 120:6497; overview 120:8390; creature states 120:9037, 120:9236, 120:9421, 168:522; Event Log 120:10052; event-list origin 160:496; hidden controls 120:10003; website pages 120:11931, 120:11955, 120:11982. Revision captures design state on October 25, 2026.
