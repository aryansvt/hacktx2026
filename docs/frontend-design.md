# M1 design evidence

Read-only Figma session fa33d2b3-bfe1-49e2-8ec8-1f7635d825bd.

Read design context and screenshots for P2 177:542, 177:580, 177:781 and wiring 120:8390, 120:8573, 120:9037, 120:9236, 120:9421, 168:522. No sparse-context response was used.

P2 tokens: background #efe3c8; surface #e1d5bc; border #a99e84; ink #1b1612; display #c8412b; blue #1f3c88; gold #d4a52b; radius 3px. Pirata One display 24-26px, EB Garamond body 15-18px and bold labels, Inter available for UI. No decorative texture or shadow was supplied for the panels.

Prototype read: Latest -> Activity; marker -> direct creature overview; feed row -> event-list-origin creature; Activity X -> overview; direct inspection X -> Activity; Replay/Details/Dossier -> same-size subviews; each subview back -> creature overview. Implementation retains feed scroll/focus and camera position through inspection.

Desktop anchors: top bar (20,20,1880,60); timeline (20,1000,1880,60); Latest (60,852,480,128); Activity (60,100,480,880); popup (60,325.5,480,429). Globe diameter 700 at center (960,540); center shifts +252 for Activity/list inspection, +237 for direct inspection. Smaller layouts reflow independently.

Mock traffic is visibly labeled. Wild-only counters stay zero because no wild events are ingested. Timeline displays the separate last-24-hour mock history, rather than inventing wild totals. LIVE indicates the fixture stream; adjacent mode selector identifies Mock.

## M1 implementation handoff — October 25, 2026

The supplied wiring structure and P2 Blue-Gold styling remain authoritative, with the precedence recorded in `docs/frontend-spec.md` and `docs/architecture.md`. This handoff records the implemented incumbent design; it does not establish a replacement visual system.

`world/src/app/globals.css` implements the seven P2 color values and 3px radius recorded above without substitution. Pirata One supplies the 24px brand and 24–26px panel headings; EB Garamond supplies the body, feed, labels and actions. The implementation adds muted text (`--muted: #574e40`), a blue 3px keyboard-focus outline and reduced-motion handling. These are implementation treatments, not additional extracted Figma tokens.

`world/src/components/live/live.module.css` shares the surface, border and radius across the top bar, timeline, Latest card and inspection/feed panels. Replay uses blue fill, parchment text and a gold border; secondary actions and evidence chips retain the parchment treatment. Panels have no decorative texture or shadow. The small shadow on world markers is a separate scene affordance. `LiveShell.tsx` keeps Replay, Details and Dossier in the same popup shell; `World.tsx` supplies the persistent 3D globe, gold fortress, projected markers and inspection anchor.

Desktop geometry follows the recorded 1920 × 1080 anchors. The implemented responsive rules reduce panel width to 420px below 1500px and 360px below 1100px; below 760px, the panels reflow beneath the globe. These smaller-layout rules are implementation adaptations, not measurements from an additional Figma frame.

Production-build review evidence is saved in `.impeccable/review/`: `desktop.jpg`, `activity.jpg`, `creature.jpg`, `replay.jpg`, `details.jpg`, and `dossier.jpg` at 1920 × 1080; `small-desktop.jpg`, `small-activity.jpg`, and `small-creature.jpg` at 1280 × 800. The nine captures show the incumbent typography, parchment panel treatment, blue/gold action styling and shared inspection geometry. They cover desktop and smaller desktop, not mobile acceptance. The finish-review disposition is **ship for M1**; this does not imply completion of later-milestone controls, live backend integration or the full frontend specification.
