import { useEffect, useState } from "react";
import { bus } from "./bus";
import { creatureKey, ranks } from "./domain";
import { useDomain } from "./store";
import { useView } from "./view-store";
import type { AttackerSummary } from "./contracts";

export type HashMode = "live" | "kiosk" | "guest";

export const parseHash = (hash: string): HashMode =>
  hash === "#kiosk" ? "kiosk" : hash === "#guest" ? "guest" : "live";

export function useHashMode() {
  const [mode, setMode] = useState<HashMode>("live");
  useEffect(() => {
    const read = () => setMode(parseHash(window.location.hash));
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  return mode;
}

// the most interesting creature to show off: tripwire hits first, then highest threat, then newest
export function pickHighlight(
  attackers: AttackerSummary[],
  tripwired: Set<string>,
): AttackerSummary | null {
  const ranked = [...attackers].sort(
    (a, b) =>
      Number(tripwired.has(b.ip_hash)) - Number(tripwired.has(a.ip_hash)) ||
      ranks[b.max_threat] - ranks[a.max_threat] ||
      b.last_seen.localeCompare(a.last_seen),
  );
  return ranked[0] ?? null;
}

// kiosk: wide shot, fly to a highlight, hold its page, back out, repeat
export function useKioskTour(on: boolean) {
  useEffect(() => {
    if (!on) return;
    const tripwired = new Set<string>();
    const off = bus.on((e) => {
      if (e.type === "tripwire") tripwired.add(creatureKey(e));
    });
    let timer: ReturnType<typeof setTimeout>;
    const wide = () => {
      useView.setState({ surface: "none", subview: "overview" });
      timer = setTimeout(visit, 9000);
    };
    const visit = () => {
      const all = Object.values(useDomain.getState().data.attackers);
      const pick = pickHighlight(all, tripwired);
      if (pick)
        useView.getState().select(pick.ip_hash, pick.latest_session_id, "map");
      timer = setTimeout(wide, 8000);
    };
    timer = setTimeout(visit, 6000);
    return () => {
      off();
      clearTimeout(timer);
    };
  }, [on]);
}

// guest: follow the newest guest creature (judges at our table in austin)
export function useGuestFollow(on: boolean) {
  useEffect(() => {
    if (!on) return;
    const follow = (key: string, session: string) =>
      useView.getState().select(key, session, "map");
    const newest = Object.values(useDomain.getState().data.attackers)
      .filter((a) => a.source === "guest")
      .sort((a, b) => b.last_seen.localeCompare(a.last_seen))[0];
    if (newest) follow(newest.ip_hash, newest.latest_session_id);
    return bus.on((e) => {
      if (e.source === "guest" && e.type === "session_start")
        follow(creatureKey(e), e.session_id);
    });
  }, [on]);
}
