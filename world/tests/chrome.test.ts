import { test } from "node:test";
import assert from "node:assert/strict";
import type {
  AttackEvent,
  Attacker,
  DetailMap,
  Source,
} from "../src/lib/contracts";
import {
  heraldFor,
  heraldCtx,
  remember,
  enqueue,
  type Queued,
} from "../src/components/chrome/herald";
import { sentence, sessionSentence } from "../src/components/chrome/sentence";
import { flagOf, ago } from "../src/components/chrome/place";

let n = 0;
function ev<T extends keyof DetailMap>(
  type: T,
  detail: DetailMap[T],
  over: {
    source?: Source;
    attacker?: Partial<Attacker>;
    country?: string;
    city?: string | null;
    session?: string;
  } = {},
): AttackEvent {
  return {
    event_id: `e${++n}`,
    session_id: over.session ?? "s1",
    type,
    timestamp: "2026-10-25T14:00:00Z",
    source: over.source ?? "wild",
    protocol: "ssh",
    geo: {
      lat: 0,
      lon: 0,
      country: over.country ?? "BG",
      city: over.city === undefined ? "Sofia" : over.city,
    },
    attacker: {
      kind: "bot",
      confidence: 0.9,
      reputation: "unknown",
      family: null,
      threat: "low",
      client: null,
      ip_hash: "a".repeat(64),
      ...over.attacker,
    },
    detail,
  } as AttackEvent;
}

test("guest login heralds a guest knight with the guest name", () => {
  const ctx = heraldCtx(["BG", "US"]);
  const e = ev(
    "session_start",
    { guest_name: "Ada" },
    {
      source: "guest",
      country: "US",
      city: "Austin",
      session: "g1",
      attacker: { ip_hash: null, kind: "human" },
    },
  );
  const h = heraldFor(e, ctx);
  assert.deepEqual(h, {
    fantasy: "A guest knight approaches from Austin",
    plain: "Ada connected over SSH at our table",
    tone: "guest",
  });
  remember(e, ctx);
  // the login that follows in the same session does not herald twice
  const again = ev(
    "login_success",
    { username: "guest" },
    { source: "guest", country: "US", city: "Austin", session: "g1" },
  );
  assert.equal(heraldFor(again, ctx), null);
});

test("guest login_success without a name says a judge", () => {
  const h = heraldFor(
    ev(
      "login_success",
      { username: "judge" },
      { source: "guest", country: "US", city: "Austin", session: "g2" },
    ),
    heraldCtx(["US"]),
  );
  assert.equal(h?.plain, "A judge connected over SSH at our table");
  assert.equal(h?.tone, "guest");
});

test("tripwire, dragon, dossier and new country heralds", () => {
  const ctx = heraldCtx(["BG"]);
  const trip = heraldFor(
    ev(
      "tripwire",
      { tripwire_id: "t", reasons: [] },
      {
        country: "DE",
        city: "Frankfurt",
        attacker: { kind: "agent", reputation: "malicious" },
      },
    ),
    ctx,
  );
  assert.equal(
    trip?.fantasy,
    "Hear ye! A cursed fae from Frankfurt fell for the tripwire",
  );
  assert.equal(trip?.plain, "AI agent read a hidden note meant only for AI");

  const dragon = ev(
    "command",
    {
      command: "ls",
      output: "",
      response_ms: 1,
      answered_by: "engine",
      techniques: [],
    },
    { attacker: { threat: "critical" } },
  );
  assert.equal(heraldFor(dragon, ctx)?.fantasy, "A dragon circles the castle!");
  remember(dragon, ctx);
  assert.equal(heraldFor(dragon, ctx), null);

  const oracle = heraldFor(
    ev(
      "dossier",
      { summary: "", sources: [] },
      { attacker: { reputation: "malicious" } },
    ),
    ctx,
  );
  assert.equal(oracle?.plain, "Web reputation lookup returned malicious");

  const fresh = ev("session_start", {}, { country: "JP", city: "Tokyo" });
  assert.equal(heraldFor(fresh, ctx)?.fantasy, "A stranger arrives from Japan!");
  remember(fresh, ctx);
  assert.equal(heraldFor(fresh, ctx), null);
  assert.equal(
    heraldFor(ev("session_start", {}, { country: "XX", city: null }), ctx),
    null,
  );
});

test("sentence reads like plain english with the creature kind", () => {
  const cmd = ev("command", {
    command: "uname -a",
    output: "",
    response_ms: 1,
    answered_by: "engine",
    techniques: [],
  });
  assert.equal(sentence(cmd), "Clay golem (bot) from Sofia ran `uname -a`");
  assert.equal(
    sentence(ev("session_end", { duration_s: 9, command_count: 68 })),
    "Clay golem (bot) from Sofia left after 68 commands",
  );
  assert.equal(
    sentence(
      ev(
        "tripwire",
        { tripwire_id: "t", reasons: [] },
        { city: "Frankfurt", attacker: { kind: "agent", reputation: "malicious" } },
      ),
    ),
    "Cursed fae (AI agent) from Frankfurt fell for a tripwire",
  );
  assert.equal(
    sentence(
      ev("classified", { reasons: [] }, { attacker: { kind: "agent" } }),
    ),
    "Fae (AI agent) from Sofia was classified as an AI agent",
  );
  assert.equal(
    sentence(ev("login_success", { username: "x" }, { city: null })),
    "Clay golem (bot) from Bulgaria logged in",
  );
});

test("session fallback sentence and helpers", () => {
  const e = ev("session_start", {});
  const s = {
    session_id: "s",
    started_at: e.timestamp,
    ended_at: e.timestamp,
    source: "wild" as const,
    geo: { ...e.geo, city: "Rümlang", country: "CH" },
    attacker: e.attacker,
    status: "ended" as const,
    login_fails: 1,
    command_count: 0,
    story: null,
  };
  assert.equal(
    sessionSentence(s),
    "Clay golem (bot) from Rümlang knocked 1 time and left",
  );
  assert.equal(flagOf("US"), "\u{1F1FA}\u{1F1F8}");
  assert.equal(flagOf("XX"), "");
  assert.equal(ago("2026-10-25T14:00:00Z", Date.parse("2026-10-25T14:02:00Z")), "2m ago");
});

test("herald queue holds three and never drops a guest", () => {
  const h = (id: string, tone: "guest" | "news"): Queued => ({
    id,
    tone,
    fantasy: id,
    plain: id,
  });
  let q = [h("a", "news"), h("b", "news"), h("c", "news")];
  assert.equal(enqueue(q, h("d", "news")).length, 3);
  q = enqueue(q, h("g", "guest"));
  assert.deepEqual(
    q.map((x) => x.id),
    ["a", "b", "g"],
  );
});
