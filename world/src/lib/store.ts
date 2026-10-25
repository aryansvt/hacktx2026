import { create } from "zustand";
import { emptyDomain, ingest, type Domain } from "./domain";
import type { AttackEvent, Snapshot } from "./contracts";
interface Store {
  data: Domain;
  ready: boolean;
  ingest: (e: AttackEvent) => void;
  hydrate: (s: Snapshot) => void;
  reset: () => void;
}
export const useDomain = create<Store>((set) => ({
  data: emptyDomain(),
  ready: false,
  ingest: (e) => set((s) => ({ data: ingest(s.data, e) })),
  hydrate: (s) =>
    set(() => {
      let data: Domain = {
        ...emptyDomain(),
        sessions: Object.fromEntries(s.sessions.map((x) => [x.session_id, x])),
        attackers: Object.fromEntries(s.attackers.map((x) => [x.ip_hash, x])),
        stats: s.stats,
      };
      for (const e of s.events) data = ingest(data, e);
      return { data, ready: true };
    }),
  reset: () => set({ data: emptyDomain(), ready: false }),
}));
