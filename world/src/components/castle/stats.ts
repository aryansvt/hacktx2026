import type { AttackEvent } from "@/lib/contracts";

export type Engine = "engine" | "llm" | "cache";

// who answered each command and how fast, from the events we've seen
export function answerSplit(events: AttackEvent[]) {
  const out: Record<Engine, { count: number; avg: number }> = {
    engine: { count: 0, avg: 0 },
    llm: { count: 0, avg: 0 },
    cache: { count: 0, avg: 0 },
  };
  const sums: Record<Engine, number> = { engine: 0, llm: 0, cache: 0 };
  for (const e of events) {
    if (e.type !== "command") continue;
    const k = e.detail.answered_by;
    out[k].count++;
    sums[k] += e.detail.response_ms;
  }
  for (const k of Object.keys(out) as Engine[])
    out[k].avg = out[k].count ? Math.round(sums[k] / out[k].count) : 0;
  return out;
}

// events per second over the last window
export function perSecond(events: AttackEvent[], now: number, windowS = 30) {
  const from = now - windowS * 1000;
  const n = events.filter((e) => Date.parse(e.timestamp) > from).length;
  return Math.round((n / windowS) * 10) / 10;
}

// the newest classifier and tripwire reasons, deduped
export function latestReasons(events: AttackEvent[], max = 8) {
  const seen = new Set<string>();
  const out: { reason: string; type: "classified" | "tripwire" }[] = [];
  for (const e of events) {
    if (e.type !== "classified" && e.type !== "tripwire") continue;
    for (const r of e.detail.reasons) {
      if (seen.has(r)) continue;
      seen.add(r);
      out.push({ reason: r, type: e.type });
      if (out.length >= max) return out;
    }
  }
  return out;
}

// raw payload with the ip_hash cut short, for the scrolling log
export function redacted(e: AttackEvent) {
  const { attacker, geo, ...rest } = e;
  return JSON.stringify({
    ...rest,
    geo: { country: geo.country, city: geo.city },
    attacker: { ...attacker, ip_hash: attacker.ip_hash ? "hidden" : null },
  });
}
