// raw dump -> public/replay/snapshot.json
// usage: npx tsx scripts/snapshot/build.ts --in .replay-raw/raw.json --budget 2000
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { anonymize, type RawDump } from "./anonymize";
import { selectSessions } from "./select";
import { creatureOf } from "../../src/lib/creatures";
import type { AttackEvent, Threat } from "../../src/lib/contracts";

const arg = (name: string, fallback: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const input = arg("in", ".replay-raw/raw.json");
const out = arg("out", "public/replay/snapshot.json");
const budget = Number(arg("budget", "2000"));

const dump = JSON.parse(readFileSync(input, "utf8")) as RawDump;
const picked = selectSessions(dump.sessions, budget);
const snap = anonymize(dump, picked);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(snap));

// what made it in, by creature
const rank: Record<Threat, number> = { low: 0, med: 1, high: 2, critical: 3 };
const last = new Map<string, AttackEvent>();
const top = new Map<string, Threat>();
for (const e of snap.events) {
  const key = e.attacker.ip_hash ?? e.session_id;
  const t = top.get(key) ?? "low";
  last.set(key, e);
  top.set(key, rank[e.attacker.threat] > rank[t] ? e.attacker.threat : t);
}
const tally: Record<string, number> = {};
for (const [key, e] of last) {
  const name =
    creatureOf(e.attacker, top.get(key), 1, e.source).name +
    (e.attacker.family ? ` (${e.attacker.family})` : "");
  tally[name] = (tally[name] ?? 0) + 1;
}
const creatures = last;
const count = (t: string) => snap.events.filter((e) => e.type === t).length;
console.log(
  `${snap.events.length} events, ${picked.length} sessions, ${creatures.size} creatures, ` +
    `${new Set(snap.events.map((e) => e.geo.country)).size} countries`,
);
console.log(
  `dossiers ${count("dossier")}, stories ${count("story")}, tripwires ${count("tripwire")}, commands ${count("command")}`,
);
console.log(tally);
console.log(
  `wrote ${out} (${(JSON.stringify(snap).length / 1024).toFixed(0)} KB)`,
);
