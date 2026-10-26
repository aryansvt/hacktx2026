import { test, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import type {
  AttackEvent,
  DetailMap,
  Snapshot,
  Stats,
} from "../src/lib/contracts";
import { emptyStats } from "../src/lib/domain";
import { useDomain } from "../src/lib/store";
import {
  buildSchedule,
  createReplayAdapter,
  lapId,
  type ReplaySnapshot,
} from "../src/lib/replay";

const k = (c: string) => c.repeat(64);
const sid = (c: string) => c.repeat(28) + "0000";
let n = 0;
function visit(
  key: string,
  session: string,
  start: string,
  steps: [number, keyof DetailMap, object][],
  extra: Partial<AttackEvent["attacker"]> = {},
  source: AttackEvent["source"] = "wild",
): AttackEvent[] {
  return steps.map(([offsetS, type, detail]) => ({
    event_id: `00000000-0000-4000-8000-0000${String(++n).padStart(4, "0")}0000`,
    session_id: session,
    type,
    timestamp: new Date(Date.parse(start) + offsetS * 1000).toISOString(),
    source,
    protocol: "ssh",
    geo: { lat: 1, lon: 2, country: "NL", city: "Amsterdam" },
    attacker: {
      kind: "bot",
      confidence: 0.9,
      reputation: "unknown",
      family: null,
      threat: "low",
      client: null,
      ip_hash: key,
      ...extra,
    },
    detail,
  })) as AttackEvent[];
}
const cmd = {
  command: "uname -a",
  output: "Linux",
  response_ms: 1,
  answered_by: "engine",
  techniques: [],
};
const end = { duration_s: 3, command_count: 1 };
function fixture(): ReplaySnapshot {
  const events = [
    ...visit(k("a"), sid("a"), "2026-10-25T10:00:00Z", [
      [0, "session_start", {}],
      [1, "login_fail", { username: "root" }],
      [3, "session_end", end],
      [30, "story", { story: "A golem knocked." }],
    ]),
    ...visit(
      k("b"),
      sid("b"),
      "2026-10-25T11:00:00Z",
      [
        [0, "session_start", {}],
        [0.1, "login_success", { username: "root" }],
        [0.2, "command", cmd],
        [0.3, "command", cmd],
        [2, "session_end", end],
        [3, "dossier", { summary: "kaiji", sources: [] }],
      ],
      { threat: "critical", reputation: "malicious", family: "kaiji" },
    ),
    ...visit(k("a"), sid("c"), "2026-10-25T12:00:00Z", [
      [0, "session_start", {}],
      [2, "session_end", end],
    ]),
    ...visit(
      k("d"),
      sid("d"),
      "2026-10-25T13:00:00Z",
      [
        [0, "session_start", {}],
        [1, "login_success", { username: "guest" }],
        [5, "session_end", end],
      ],
      { kind: "human" },
      "guest",
    ),
  ];
  const stats: Stats = {
    ...emptyStats,
    total_sessions: 4985,
    countries: 20,
    breaches: 230,
    per_minute: [
      { t: "2026-10-25T10:00:00.000Z", bot: 1, human: 0, agent: 0 },
      { t: "2026-10-26T07:17:00.000Z", bot: 2, human: 0, agent: 0 },
    ],
  };
  return {
    version: 1,
    recorded: { from: events[0].timestamp, to: events.at(-1)!.timestamp },
    stats,
    visits: { [k("a")]: 40, [k("b")]: 1, [k("d")]: 1 },
    events,
  };
}
const TARGET = 60_000;
const make = () =>
  createReplayAdapter({ load: async () => fixture(), targetMs: TARGET });

beforeEach(() => {
  mock.timers.enable({
    apis: ["setTimeout", "Date"],
    now: Date.parse("2026-11-01T12:00:00Z"),
  });
  useDomain.getState().reset();
});
afterEach(() => {
  mock.timers.reset();
  delete (globalThis as { document?: unknown }).document;
});

test("buildSchedule keeps recorded order and caps gaps inside a visit", () => {
  const f = fixture();
  const s = buildSchedule(f.events, TARGET);
  const ats = s.items.map((i) => i.at);
  assert.deepEqual(
    ats,
    [...ats].sort((a, b) => a - b),
  );
  for (const id of [sid("a"), sid("b")]) {
    const mine = s.items.filter((i) => i.event.session_id === id);
    assert.deepEqual(
      mine.map((i) => i.event),
      f.events.filter((e) => e.session_id === id),
    );
  }
  const a = s.items.filter((i) => i.event.session_id === sid("a"));
  assert.equal(a.at(-1)!.at - a.at(-2)!.at, 4000);
  assert.ok(s.lapMs > s.items.at(-1)!.at && s.lapMs <= TARGET + 10_000);
});

test("buildSchedule squeezes a long recording into about the target", () => {
  const events = Array.from({ length: 120 }, (_, i) =>
    visit(
      k("e"),
      `${i}`.padStart(28, "e") + "0000",
      new Date(Date.parse("2026-10-25T10:00:00Z") + i * 600_000).toISOString(),
      [
        [0, "session_start", {}],
        [1, "session_end", end],
      ],
    ),
  ).flat();
  const s = buildSchedule(events, 12 * 60_000);
  assert.ok(Math.abs(s.lapMs - 12 * 60_000) < 60_000, `lap ${s.lapMs}`);
});

test("lapId rewrites the tail and keeps the uuid shape", () => {
  const id = "123e4567-e89b-42d3-a456-426614170000";
  assert.equal(lapId(id, 0), id);
  assert.equal(lapId(id, 3), "123e4567-e89b-42d3-a456-426614170003");
  assert.equal(lapId(sid("a"), 300).length, 32);
  assert.notEqual(lapId(id, 1), lapId(id, 2));
});

test("snapshot starts with every creature at its recorded visits and no sessions", async () => {
  const adapter = make();
  assert.equal(adapter.mode, "replay");
  const snap = await adapter.snapshot();
  assert.equal(snap.attackers.length, 3);
  assert.equal(snap.sessions.length, 0);
  assert.equal(snap.events.length, 0);
  assert.equal(snap.attackers.find((a) => a.ip_hash === k("a"))!.visits, 40);
  const dragon = snap.attackers.find((a) => a.ip_hash === k("b"))!;
  assert.equal(dragon.max_threat, "critical");
  assert.equal(dragon.attacker.family, "kaiji");
  assert.ok(Date.parse(dragon.last_seen) < Date.now());
  assert.equal(snap.stats.total_sessions, 4985);
  assert.equal(snap.stats.breaches, 230);
  const lastMinute = Date.parse(snap.stats.per_minute.at(-1)!.t);
  assert.ok(Date.now() - lastMinute < 120_000 && lastMinute <= Date.now());
});

test("events play restamped to now", async () => {
  const adapter = make();
  await adapter.snapshot();
  const got: AttackEvent[] = [];
  adapter.subscribe((e) => got.push(e));
  mock.timers.tick(3000);
  assert.ok(got.length > 0);
  assert.equal(got[0].type, "session_start");
  for (const e of got)
    assert.ok(Math.abs(Date.parse(e.timestamp) - Date.now()) < 3100);
  adapter.close();
});

test("each lap re-hydrates and uses new ids", async () => {
  const adapter = make();
  const base = await adapter.snapshot();
  const lap = buildSchedule(fixture().events, TARGET).lapMs;
  const got: AttackEvent[] = [];
  const resets: Snapshot[] = [];
  adapter.subscribe((e) => got.push(e), { reset: (s) => resets.push(s) });
  for (let t = 0; t < lap + 3000; t += 500) mock.timers.tick(500);
  assert.equal(resets.length, 1);
  assert.equal(resets[0].sessions.length, 0);
  assert.equal(resets[0].attackers.length, base.attackers.length);
  const firstLap = got.filter((e) => e.event_id.endsWith("0001"));
  const secondLap = got.filter((e) => e.event_id.endsWith("0002"));
  assert.equal(firstLap.length, fixture().events.length);
  assert.ok(secondLap.length > 0);
  assert.ok(secondLap.every((e) => e.session_id.endsWith("0002")));
  adapter.close();
});

test("visit counts stay at the recorded value across laps", async () => {
  const adapter = make();
  const store = useDomain.getState();
  store.hydrate(await adapter.snapshot());
  const lap = buildSchedule(fixture().events, TARGET).lapMs;
  adapter.subscribe(useDomain.getState().ingest, {
    reset: useDomain.getState().hydrate,
  });
  for (let t = 0; t < lap * 2 + 5000; t += 500) mock.timers.tick(500);
  const { attackers, sessions } = useDomain.getState().data;
  assert.equal(attackers[k("a")].visits, 40);
  assert.equal(attackers[k("b")].visits, 1);
  assert.equal(attackers[k("d")].visits, 1);
  assert.ok(Object.keys(sessions).length <= 4);
  adapter.close();
});

test("session() serves past laps fully and the current lap only up to now", async () => {
  const adapter = make();
  await adapter.snapshot();
  const sched = buildSchedule(fixture().events, TARGET);
  adapter.subscribe(() => {});
  const b = sched.sessions[sid("b")];
  for (let t = 0; t < b.start + 150; t += 250)
    mock.timers.tick(Math.min(250, b.start + 150 - t));
  const live = await adapter.session(lapId(sid("b"), 1));
  const all = fixture().events.filter((e) => e.session_id === sid("b"));
  assert.ok(live.events.length > 0 && live.events.length < all.length);
  assert.ok(live.events.every((e) => Date.parse(e.timestamp) <= Date.now()));
  assert.equal(live.session.status, "inside");
  const past = await adapter.session(sid("b"));
  assert.equal(past.events.length, all.length);
  assert.equal(past.session.status, "ended");
  await assert.rejects(adapter.session(lapId(sid("d"), 1)));
  adapter.close();
});

test("a hidden tab pauses the replay instead of flooding on return", async () => {
  const listeners: Record<string, () => void> = {};
  const doc = {
    hidden: false,
    addEventListener: (t: string, fn: () => void) => (listeners[t] = fn),
    removeEventListener: () => {},
  };
  (globalThis as { document?: unknown }).document = doc;
  const adapter = make();
  await adapter.snapshot();
  const got: AttackEvent[] = [];
  adapter.subscribe((e) => got.push(e));
  mock.timers.tick(2000);
  const before = got.length;
  doc.hidden = true;
  listeners.visibilitychange();
  for (let t = 0; t < 600_000; t += 1000) mock.timers.tick(1000);
  assert.equal(got.length, before);
  doc.hidden = false;
  listeners.visibilitychange();
  mock.timers.tick(100);
  assert.ok(got.length - before <= 2, `flooded ${got.length - before}`);
  adapter.close();
});

test("stats push active visitors from the schedule", async () => {
  const adapter = make();
  await adapter.snapshot();
  const sched = buildSchedule(fixture().events, TARGET);
  const pushed: Stats[] = [];
  adapter.subscribe(() => {}, { stats: (s) => pushed.push(s) });
  const a = sched.sessions[sid("a")];
  mock.timers.tick(a.start + 500);
  assert.equal(pushed.at(-1)!.active_now, 1);
  assert.equal(pushed.at(-1)!.total_sessions, 4985);
  for (let t = a.start + 500; t < a.end + 1000; t += 250) mock.timers.tick(250);
  assert.equal(pushed.at(-1)!.active_now, 0);
  adapter.close();
});

test("a stalled timer (laptop asleep) counts as a pause, not a backlog", async () => {
  const adapter = make();
  await adapter.snapshot();
  const got: AttackEvent[] = [];
  adapter.subscribe((e) => got.push(e));
  for (let t = 0; t < 2000; t += 250) mock.timers.tick(250);
  const before = got.length;
  // one jump: the clock moves ten minutes before the next timer runs
  mock.timers.tick(600_000);
  assert.ok(got.length - before <= 3, `flooded ${got.length - before}`);
  adapter.close();
});
