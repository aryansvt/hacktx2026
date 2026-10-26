// pulls everything the read api exposes into one raw dump. the dump keeps
// hashed ids and unscrubbed commands, so it stays out of git (.replay-raw/).
// usage: npx tsx scripts/snapshot/fetch.ts --api http://localhost:8000 --out .replay-raw/raw.json
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type {
  AttackerSummary,
  SessionResponse,
  SessionSummary,
  Stats,
} from "../../src/lib/contracts";
import type { RawDump } from "./anonymize";

const arg = (name: string, fallback: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const api = arg("api", "http://localhost:8000").replace(/\/$/, "");
const out = arg("out", ".replay-raw/raw.json");
const sources = ["wild", "guest", "team"] as const;

async function get<T>(path: string): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(api + path);
    if (res.ok) return (await res.json()) as T;
    if (attempt >= 3 || res.status === 404)
      throw new Error(`${path} returned ${res.status}`);
    await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
  }
}

// runs fn over items with a few requests in flight at once
async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>) {
  const results: R[] = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: n }, async () => {
      while (next < items.length) {
        const i = next++;
        results[i] = await fn(items[i]);
      }
    }),
  );
  return results;
}

async function main() {
  const stats = await get<Stats>("/stats");
  const attackers: AttackerSummary[] = [];
  const ids = new Set<string>();
  for (const s of sources) {
    const rows = await get<AttackerSummary[]>(`/attackers?limit=500&source=${s}`);
    attackers.push(...rows);
    for (const a of rows) for (const id of a.session_ids) ids.add(id);
    const recent = await get<SessionSummary[]>(`/sessions?limit=200&source=${s}`);
    for (const r of recent) ids.add(r.session_id);
  }
  console.log(`${attackers.length} attackers, ${ids.size} sessions to fetch`);
  let done = 0;
  const sessions = (
    await pool([...ids], 6, async (id) => {
      try {
        const res = await get<SessionResponse>(`/sessions/${id}`);
        if (++done % 100 === 0) console.log(`  ${done}/${ids.size}`);
        return res;
      } catch (err) {
        console.warn(`  skipped ${id}: ${(err as Error).message}`);
        return null;
      }
    })
  ).filter((s): s is SessionResponse => s !== null);
  const dump: RawDump = {
    fetched_at: new Date().toISOString(),
    stats,
    attackers,
    sessions,
  };
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(dump));
  const events = sessions.reduce((n, s) => n + s.events.length, 0);
  console.log(`wrote ${out}: ${sessions.length} sessions, ${events} events`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
