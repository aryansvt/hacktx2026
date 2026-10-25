// pure globe math, no three.js so it runs in node tests
export type V3 = [number, number, number];

export const GLOBE_R = 2;
export const CASTLE = { lat: 32.78, lon: -96.8 };

// same mapping the old world used: lat/lon to a point on a sphere of radius r
export function toXYZ(lat: number, lon: number, r = GLOBE_R): V3 {
  const la = (lat * Math.PI) / 180,
    lo = (lon * Math.PI) / 180;
  return [
    Math.cos(la) * Math.sin(lo) * r,
    Math.sin(la) * r,
    Math.cos(la) * Math.cos(lo) * r,
  ];
}

export const len = (v: V3) => Math.hypot(v[0], v[1], v[2]);
export const norm = (v: V3): V3 => {
  const l = len(v) || 1;
  return [v[0] / l, v[1] / l, v[2] / l];
};
export const dot = (a: V3, b: V3) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
export const scale = (v: V3, s: number): V3 => [v[0] * s, v[1] * s, v[2] * s];

// spherical interpolation between two directions, returns a unit vector
export function slerp(a: V3, b: V3, t: number): V3 {
  const ua = norm(a),
    ub = norm(b);
  const angle = Math.acos(Math.max(-1, Math.min(1, dot(ua, ub))));
  if (angle < 1e-6) return ua;
  const s = Math.sin(angle);
  const wa = Math.sin((1 - t) * angle) / s,
    wb = Math.sin(t * angle) / s;
  return norm([
    ua[0] * wa + ub[0] * wb,
    ua[1] * wa + ub[1] * wb,
    ua[2] * wa + ub[2] * wb,
  ]);
}

// point on a raised great-circle arc. lift scales with arc length so short hops stay low
export function arcPoint(a: V3, b: V3, t: number, r = GLOBE_R, lift = 0.35): V3 {
  const angle = Math.acos(Math.max(-1, Math.min(1, dot(norm(a), norm(b)))));
  const h = Math.sin(t * Math.PI) * lift * Math.min(1, angle / 1.2 + 0.08);
  return scale(slerp(a, b, t), r + h);
}

export type Status = "approaching" | "at_gate" | "inside" | "ended";

// how far along the trail (0 origin, 1 gate) a creature stands for its session status
export function progressFor(status: Status, elapsedMs = 0): number {
  if (status === "at_gate" || status === "inside") return 1;
  if (status === "ended") return 0;
  const k = Math.max(0, Math.min(1, elapsedMs / 30_000));
  return 0.1 + 0.5 * k;
}

// small stable hash in [0, 1) so slots and phases never jump between renders
export function hash01(s: string, salt = 0): number {
  let h = 2166136261 ^ salt;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 100000) / 100000;
}

// a spot on the gate ring around the castle, offset on the surface by angle and radius
export function gateSlot(key: string, castle: V3, inner = 0.23, outer = 0.38): V3 {
  const up = norm(castle);
  // tangent basis at the castle
  const ref: V3 = Math.abs(up[1]) > 0.9 ? [1, 0, 0] : [0, 1, 0];
  const e1 = norm(cross(ref, up));
  const e2 = cross(up, e1);
  const a = hash01(key, 1) * Math.PI * 2;
  const d = inner + hash01(key, 2) * (outer - inner);
  const r = len(castle);
  const p: V3 = [
    castle[0] + (e1[0] * Math.cos(a) + e2[0] * Math.sin(a)) * d,
    castle[1] + (e1[1] * Math.cos(a) + e2[1] * Math.sin(a)) * d,
    castle[2] + (e1[2] * Math.cos(a) + e2[2] * Math.sin(a)) * d,
  ];
  return scale(norm(p), r);
}

export function cross(a: V3, b: V3): V3 {
  return [
    a[1] * b[2] - a[2] * b[1],
    a[2] * b[0] - a[0] * b[2],
    a[0] * b[1] - a[1] * b[0],
  ];
}

export const easeInOut = (t: number) =>
  t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
