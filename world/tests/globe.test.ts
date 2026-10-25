import { test } from "node:test";
import assert from "node:assert/strict";
import {
  arcPoint,
  CASTLE,
  gateSlot,
  len,
  progressFor,
  slerp,
  toXYZ,
  dot,
  norm,
} from "../src/components/globe/geo";

const close = (a: number, b: number, eps = 1e-6) =>
  assert.ok(Math.abs(a - b) < eps, `${a} != ${b}`);

test("toXYZ puts lat/lon on the sphere", () => {
  close(len(toXYZ(32.78, -96.8)), 2);
  const north = toXYZ(90, 0);
  close(north[1], 2);
  const front = toXYZ(0, 0);
  close(front[2], 2);
});

test("slerp hits both ends and stays on the unit sphere", () => {
  const a = toXYZ(52.5, 13.4),
    b = toXYZ(CASTLE.lat, CASTLE.lon);
  const s0 = slerp(a, b, 0),
    s1 = slerp(a, b, 1),
    mid = slerp(a, b, 0.5);
  close(dot(s0, norm(a)), 1);
  close(dot(s1, norm(b)), 1);
  close(len(mid), 1);
  // midpoint is equally far from both ends
  close(dot(mid, norm(a)), dot(mid, norm(b)));
});

test("arcPoint is raised in the middle and grounded at the ends", () => {
  const a = toXYZ(35.7, 139.7),
    b = toXYZ(CASTLE.lat, CASTLE.lon);
  close(len(arcPoint(a, b, 0)), 2);
  close(len(arcPoint(a, b, 1)), 2);
  assert.ok(len(arcPoint(a, b, 0.5)) > 2.2);
});

test("progressFor maps session status to a spot on the trail", () => {
  assert.equal(progressFor("ended"), 0);
  assert.equal(progressFor("at_gate"), 1);
  assert.equal(progressFor("inside"), 1);
  close(progressFor("approaching", 0), 0.1);
  close(progressFor("approaching", 60_000), 0.6);
  assert.ok(
    progressFor("approaching", 15_000) < progressFor("approaching", 25_000),
  );
});

test("gateSlot is stable, on the surface, and near the castle", () => {
  const c = toXYZ(CASTLE.lat, CASTLE.lon);
  const p = gateSlot("abc", c),
    q = gateSlot("abc", c);
  assert.deepEqual(p, q);
  close(len(p), 2);
  const d = Math.hypot(p[0] - c[0], p[1] - c[1], p[2] - c[2]);
  assert.ok(d > 0.1 && d < 0.4, `distance ${d}`);
});
