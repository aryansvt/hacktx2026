import { test } from "node:test";
import assert from "node:assert/strict";
import type { AttackEvent } from "../src/lib/contracts";
import {
  domainOf,
  enqueue,
  lineOf,
  reasonsOf,
  relativeTime,
  replayEvents,
  replayGaps,
} from "../src/components/creature/replay";

const base = {
  session_id: "s1",
  source: "wild",
  protocol: "ssh",
  geo: { lat: 0, lon: 0, country: "NL", city: "Amsterdam" },
  attacker: {
    kind: "bot",
    confidence: 0.9,
    reputation: "malicious",
    family: null,
    threat: "high",
    client: null,
    ip_hash: "h",
  },
} as const;
const ev = (
  id: string,
  t: string,
  type: AttackEvent["type"],
  detail: unknown,
): AttackEvent =>
  ({ ...base, event_id: id, timestamp: t, type, detail }) as AttackEvent;

test("replay gaps use real timing, capped and floored", () => {
  const gaps = replayGaps([
    { timestamp: "2026-10-25T10:00:00.000Z" },
    { timestamp: "2026-10-25T10:00:01.000Z" },
    { timestamp: "2026-10-25T10:05:00.000Z" },
    { timestamp: "2026-10-25T10:05:00.010Z" },
    { timestamp: "nope" },
  ]);
  assert.deepEqual(gaps, [0, 1000, 2500, 250, 250]);
});

test("domainOf strips www and survives bad urls", () => {
  assert.equal(domainOf("https://www.abuseipdb.com/check/1"), "abuseipdb.com");
  assert.equal(domainOf("greynoise.io/viz"), "greynoise.io");
});

test("reasons come from the latest classified event", () => {
  const events = [
    ev("1", "2026-10-25T10:00:00Z", "classified", { reasons: ["old"] }),
    ev("2", "2026-10-25T10:00:01Z", "tripwire", {
      tripwire_id: "t",
      reasons: ["trip"],
    }),
    ev("3", "2026-10-25T10:00:02Z", "classified", {
      reasons: ["burst timing", "burst timing", "repeated login failures"],
    }),
  ];
  assert.deepEqual(reasonsOf(events), [
    "burst timing",
    "repeated login failures",
  ]);
  assert.deepEqual(reasonsOf([events[1]]), ["trip"]);
  assert.deepEqual(reasonsOf([]), []);
});

test("replay lines skip enrichment and never show passwords", () => {
  const events = [
    ev("1", "2026-10-25T10:00:00Z", "login_fail", { username: "root" }),
    ev("2", "2026-10-25T10:00:01Z", "classified", { reasons: [] }),
    ev("3", "2026-10-25T10:00:02Z", "command", {
      command: "uname -a",
      output: "Linux",
      response_ms: 4,
      answered_by: "engine",
      techniques: [],
    }),
  ];
  const steps = replayEvents(events);
  assert.equal(steps.length, 2);
  assert.equal(lineOf(steps[0])?.text, "login as root failed");
  assert.deepEqual(lineOf(steps[1]), {
    id: "3",
    tone: "cmd",
    text: "uname -a",
    output: "Linux",
    tag: "engine",
  });
});

test("relative time reads plainly", () => {
  const now = Date.parse("2026-10-25T10:00:00Z");
  assert.equal(relativeTime("2026-10-25T09:59:58Z", now), "just now");
  assert.equal(relativeTime("2026-10-25T09:59:30Z", now), "30s ago");
  assert.equal(relativeTime("2026-10-25T09:50:00Z", now), "10 min ago");
  assert.equal(relativeTime("2026-10-25T07:00:00Z", now), "3h ago");
  assert.equal(relativeTime("bad", now), "unknown");
});

test("oracle queue keeps the newest three", () => {
  let q: number[] = [];
  for (const n of [1, 2, 3, 4, 5]) q = enqueue(q, n, 3);
  assert.deepEqual(q, [3, 4, 5]);
});
