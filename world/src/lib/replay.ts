import type { AttackEvent, Stats } from "./contracts";

// public/replay/snapshot.json, written by scripts/snapshot/build.ts
export interface ReplaySnapshot {
  version: 1;
  recorded: { from: string; to: string };
  // real wild totals when the snapshot was taken
  stats: Stats;
  // recorded visit count per creature (re-keyed ip_hash)
  visits: Record<string, number>;
  events: AttackEvent[];
}
