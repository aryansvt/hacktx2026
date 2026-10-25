import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { fixtures, fixtureEvent, createMockAdapter } from "../src/lib/mock";
import { envMode } from "../src/lib/data-mode";
import { backoff } from "../src/lib/live";
import { creatureKey } from "../src/lib/domain";
import {
  emptyDomain,
  ingest,
  activeVisits,
  parseTransport,
  appearance,
} from "../src/lib/domain";
import { useView } from "../src/lib/view-store";
const ajv = new Ajv({ strict: false });
addFormats(ajv);
const validator = (name: string) =>
  ajv.compile(
    JSON.parse(readFileSync(`../contracts/${name}.schema.json`, "utf8")),
  );
test("fixtures satisfy exact public schemas including wrapped replay", async () => {
  const adapter = createMockAdapter();
  const snapshot = await adapter.snapshot();
  for (const [name, rows] of [
    ["event", snapshot.events],
    ["session_summary", snapshot.sessions],
    ["attacker_summary", snapshot.attackers],
    ["stats", [snapshot.stats]],
  ] as const) {
    const valid = validator(name);
    for (const row of rows) assert.ok(valid(row), JSON.stringify(valid.errors));
  }
  const replay = await adapter.session("fixture-visit-1");
  assert.equal(replay.session.session_id, "fixture-visit-1");
  assert.ok(replay.events.some((e) => e.type === "command"));
  const empty = await adapter.session("fixture-visit-4");
  assert.equal(empty.events.filter((e) => e.type === "command").length, 0);
  adapter.close();
});
test("group by hash; repeat visits and ending one overlapping visit retain creature", () => {
  const state = fixtures().reduce(ingest, emptyDomain());
  assert.equal(Object.keys(state.attackers).length, 7);
  assert.equal(state.attackers["1".repeat(64)].visits, 2);
  assert.equal(activeVisits(state, "1".repeat(64)), 1);
  assert.equal(state.stats.total_sessions, 0);
});
test("duplicates are no-ops; pings never mutate domain", () => {
  let state = fixtures().reduce(ingest, emptyDomain());
  assert.equal(ingest(state, fixtures()[0]), state);
  const before = state;
  for (let i = 0; i < 20; i++) {
    const event = parseTransport('{"type":"ping"}');
    if (event) state = ingest(state, event);
  }
  assert.equal(state, before);
  assert.equal(parseTransport("bad json"), null);
});
test("late unknown arrivals preserve aggregate classification and maximum threat", () => {
  let state = fixtures().reduce(ingest, emptyDomain());
  const event = fixtureEvent(0, "return-unknown", "session_start", {}, 1000);
  event.attacker = {
    ...event.attacker,
    kind: "unknown",
    confidence: 0,
    threat: "low",
  };
  state = ingest(state, event);
  assert.equal(state.attackers["1".repeat(64)].attacker.kind, "bot");
  assert.equal(state.attackers["1".repeat(64)].max_threat, "high");
  const reversed = fixtures().reverse().reduce(ingest, emptyDomain());
  assert.equal(reversed.sessions["fixture-visit-1"].status, "ended");
  assert.equal(
    appearance(reversed.attackers["6".repeat(64)].attacker).name,
    "Dragon",
  );
});
test("subview back restores overview and close preserves activity source", () => {
  const v = useView.getState();
  v.openActivity();
  v.select("a", "visit", "activity", "row");
  v.view("replay");
  assert.equal(useView.getState().surface, "creature");
  v.back();
  assert.equal(useView.getState().subview, "overview");
  v.close();
  assert.equal(useView.getState().surface, "activity");
  assert.equal(useView.getState().focusId, "row");
  v.close();
  assert.equal(useView.getState().surface, "none");
  v.select("a", "visit", "map");
  v.close();
  assert.equal(useView.getState().surface, "activity");
});
test("configuration compares the flag explicitly", () => {
  assert.equal(envMode("0"), "live");
  assert.equal(envMode("1"), "mock");
  assert.equal(envMode(undefined), "live");
  assert.equal(envMode("true"), "live");
});

test("reconnect backoff is 1, 2, 4 and caps at 10s", () => {
  assert.deepEqual(
    [0, 1, 2, 3, 4, 9].map(backoff),
    [1000, 2000, 4000, 8000, 10000, 10000],
  );
});
test("guest visits without ip_hash become their own creature", () => {
  const e = fixtureEvent(
    2,
    "guest-1",
    "session_start",
    { guest_name: "Ada" },
    1,
  );
  const guest = {
    ...e,
    source: "guest" as const,
    attacker: { ...e.attacker, ip_hash: null },
  };
  assert.equal(creatureKey(guest), "guest:guest-1");
  const state = ingest(emptyDomain(), guest);
  assert.ok(state.attackers["guest:guest-1"]);
});
test("live events never lower rest session counts", () => {
  const e = fixtureEvent(0, "s1", "login_fail", { username: "root" }, 1);
  const base = ingest(emptyDomain(), e);
  base.sessions.s1 = { ...base.sessions.s1, login_fails: 9, command_count: 4 };
  const next = ingest(
    base,
    fixtureEvent(0, "s1", "login_fail", { username: "admin" }, 2),
  );
  assert.equal(next.sessions.s1.login_fails, 9);
  assert.equal(next.sessions.s1.command_count, 4);
});
