# Globe data

land-points.json is generated from world-atlas 2 land-110m.json (Natural Earth 1:110m land data) using `node scripts/generate-land.cjs` from world/. World Atlas is ISC licensed; the notice is included here. Natural Earth data is public domain.

The globe, fortress, dynamic great-circle arcs and placeholder octahedra are Three.js geometry. Figma's guide-circle images are reference-only, as explicitly required by the implementation brief. No screenshot is used as an application asset. The popup anchor follows the selected projected 3D marker rather than using a static Figma guide asset.

Fonts are locally bundled through @fontsource (Pirata One, EB Garamond, Inter). Lucide provides the Simple Design System-compatible 24px icons at 1.5px stroke; the checkout has no existing Code Connect component implementation.
