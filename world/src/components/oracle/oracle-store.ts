import { create } from "zustand";
import type { AttackEvent } from "@/lib/contracts";
import { enqueue } from "../creature/replay";

type Dossier = Extract<AttackEvent, { type: "dossier" }>;

interface OracleState {
  current: Dossier | null;
  queue: Dossier[];
  push: (e: Dossier) => void;
  next: () => void;
}

// one oracle moment at a time, at most 3 waiting
export const useOracle = create<OracleState>((set) => ({
  current: null,
  queue: [],
  push: (e) =>
    set((s) =>
      s.current?.event_id === e.event_id ||
      s.queue.some((q) => q.event_id === e.event_id)
        ? s
        : s.current
          ? { queue: enqueue(s.queue, e, 3) }
          : { current: e },
    ),
  next: () =>
    set((s) => ({ current: s.queue[0] ?? null, queue: s.queue.slice(1) })),
}));

// demo hook: play the oracle for any dossier event
export function triggerOracle(e: AttackEvent) {
  if (e.type === "dossier") useOracle.getState().push(e);
}
