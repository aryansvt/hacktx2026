/* eslint-disable @typescript-eslint/no-require-imports */
const fs = require("fs");
const { feature } = require(process.cwd() + "/node_modules/topojson-client");
const topo = require(
  process.cwd() + "/node_modules/world-atlas/land-110m.json",
);
const result = feature(topo, topo.objects.land);
const land = result.features ? result.features[0] : result;
const polygons =
  land.geometry.type === "MultiPolygon"
    ? land.geometry.coordinates
    : [land.geometry.coordinates];
function ring(p, r) {
  let inside = false;
  for (let i = 0, j = r.length - 1; i < r.length; j = i++) {
    const a = r[i],
      b = r[j];
    if (
      a[1] > p[1] !== b[1] > p[1] &&
      p[0] < ((b[0] - a[0]) * (p[1] - a[1])) / (b[1] - a[1]) + a[0]
    )
      inside = !inside;
  }
  return inside;
}
const dots = [];
for (let lat = -58; lat < 84; lat += 1.65) {
  for (
    let lon = -180;
    lon < 180;
    lon += 1.65 / Math.cos((lat * Math.PI) / 180)
  ) {
    if (
      polygons.some(
        (p) =>
          ring([lon, lat], p[0]) &&
          !p.slice(1).some((r) => ring([lon, lat], r)),
      )
    ) {
      const a = (lat * Math.PI) / 180,
        b = (lon * Math.PI) / 180;
      dots.push(
        ...[
          Math.cos(a) * Math.sin(b) * 2.008,
          Math.sin(a) * 2.008,
          Math.cos(a) * Math.cos(b) * 2.008,
        ].map((x) => +x.toFixed(5)),
      );
    }
  }
}
fs.writeFileSync("src/data/land-points.json", JSON.stringify(dots));
