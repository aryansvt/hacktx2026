import { test } from "node:test";
import assert from "node:assert/strict";
import { fixtureEvent } from "../src/lib/mock";
import {
  answerSplit,
  latestReasons,
  perSecond,
  redacted,
} from "../src/components/castle/stats";

const cmd = (n: number, by: "engine" | "llm" | "cache", ms: number) =>
  fixtureEvent(
    0,
    "s",
    "command",
    {
      command: "ls",
      output: "",
      response_ms: ms,
      answered_by: by,
      techniques: [],
    },
    n,
  );

test("answer split averages response time per engine", () => {
  const s = answerSplit([
    cmd(1, "engine", 10),
    cmd(2, "engine", 30),
    cmd(3, "llm", 900),
  ]);
  assert.deepEqual(s.engine, { count: 2, avg: 20 });
  assert.deepEqual(s.llm, { count: 1, avg: 900 });
  assert.deepEqual(s.cache, { count: 0, avg: 0 });
});

test("events per second counts the recent window only", () => {
  const e = cmd(1, "engine", 1);
  const now = Date.parse(e.timestamp);
  assert.equal(perSecond([e, e, e], now + 1000, 30), 0.1);
  assert.equal(perSecond([e], now + 60_000, 30), 0);
});

test("reasons dedupe and tag tripwires", () => {
  const c = fixtureEvent(0, "s", "classified", { reasons: ["a", "b"] }, 1);
  const t = fixtureEvent(
    1,
    "s",
    "tripwire",
    { tripwire_id: "x", reasons: ["b", "c"] },
    2,
  );
  assert.deepEqual(
    latestReasons([c, t]).map((r) => `${r.type}:${r.reason}`),
    ["classified:a", "classified:b", "tripwire:c"],
  );
});

test("raw log never shows ip_hash or coordinates", () => {
  const raw = redacted(cmd(1, "engine", 1));
  assert.ok(!raw.includes("1111111111"));
  assert.ok(!raw.includes('"lat"'));
  assert.ok(raw.includes('"ip_hash":"hidden"'));
});

test("chimes only for notable events", async () => {
  const { chimeFor } = await import("../src/components/sound/chime");
  assert.equal(
    chimeFor(fixtureEvent(0, "s", "login_fail", { username: "x" }, 1)),
    null,
  );
  assert.ok(
    chimeFor(
      fixtureEvent(1, "s", "tripwire", { tripwire_id: "t", reasons: [] }, 2),
    ),
  );
  const guest = {
    ...fixtureEvent(2, "g", "session_start", {}, 3),
    source: "guest" as const,
  };
  assert.ok(chimeFor(guest));
});
