import { create } from "zustand";
import { emptyDomain, ingest, type Domain } from "./domain";
import type { AttackEvent, Snapshot, Stats } from "./contracts";
import { bus } from "./bus";
interface Store {
  data: Domain;
  ready: boolean;
  ingest: (e: AttackEvent) => void;
  hydrate: (s: Snapshot) => void;
  setStats: (s: Stats) => void;
  reset: () => void;
}
export const useDomain = create<Store>((set) => ({
  data: emptyDomain(),
  ready: false,
  ingest: (e) => {
    const seen = !!useDomain.getState().data.events[e.event_id];
    set((s) => ({ data: ingest(s.data, e) }));
    if (!seen) bus.emit(e);
  },
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
  setStats: (stats) => set((s) => ({ data: { ...s.data, stats } })),
  reset: () => set({ data: emptyDomain(), ready: false }),
}));
