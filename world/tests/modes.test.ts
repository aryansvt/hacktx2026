import { test } from "node:test";
import assert from "node:assert/strict";
import { parseHash, pickHighlight } from "../src/lib/modes";
import type { AttackerSummary } from "../src/lib/contracts";

const a = (
  ip_hash: string,
  max_threat: AttackerSummary["max_threat"],
  last_seen: string,
): AttackerSummary => ({
  ip_hash,
  visits: 1,
  first_seen: last_seen,
  last_seen,
  latest_session_id: `s-${ip_hash}`,
  source: "wild",
  geo: { lat: 0, lon: 0, country: "US", city: "Austin" },
  attacker: {
    kind: "bot",
    confidence: 0.9,
    reputation: "unknown",
    family: null,
    threat: max_threat,
  },
  max_threat,
  session_ids: [`s-${ip_hash}`],
});

test("hash modes default to live", () => {
  assert.equal(parseHash(""), "live");
  assert.equal(parseHash("#live"), "live");
  assert.equal(parseHash("#kiosk"), "kiosk");
  assert.equal(parseHash("#guest"), "guest");
  assert.equal(parseHash("#nope"), "live");
});

test("kiosk highlight prefers tripwire, then threat, then newest", () => {
  const low = a("low", "low", "2026-10-25T10:00:00Z");
  const high = a("high", "high", "2026-10-25T09:00:00Z");
  const newerHigh = a("high2", "high", "2026-10-25T09:30:00Z");
  assert.equal(
    pickHighlight([low, high, newerHigh], new Set())?.ip_hash,
    "high2",
  );
  assert.equal(pickHighlight([low, high], new Set(["low"]))?.ip_hash, "low");
  assert.equal(pickHighlight([], new Set()), null);
});
