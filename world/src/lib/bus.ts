import type { AttackEvent } from "./contracts";

// fires once per new event (after dedupe), for effects, heralds and the oracle
type Listener = (e: AttackEvent) => void;
const listeners = new Set<Listener>();

export const bus = {
  on(fn: Listener) {
    listeners.add(fn);
    return () => {
      listeners.delete(fn);
    };
  },
  emit(e: AttackEvent) {
    for (const fn of listeners) fn(e);
  },
};
