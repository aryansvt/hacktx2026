import type { AttackEvent } from "../../lib/contracts";
import { creatureOf } from "../../lib/creatures";
import { countryName, placeOf } from "./place";

export type Tone = "guest" | "danger" | "oracle" | "news";
export interface Herald {
  fantasy: string;
  plain: string;
  tone: Tone;
}
// what this browser has already announced
export interface HeraldCtx {
  countries: Set<string>;
  guests: Set<string>; // session ids
  dragons: Set<string>; // ip hashes or session ids
}
export const heraldCtx = (countries: Iterable<string> = []): HeraldCtx => ({
  countries: new Set(countries),
  guests: new Set(),
  dragons: new Set(),
});

const who = (e: AttackEvent) => e.attacker.ip_hash ?? e.session_id;

// pure: decides the banner for an event, or null
export function heraldFor(e: AttackEvent, ctx: HeraldCtx): Herald | null {
  if (
    e.source === "guest" &&
    (e.type === "session_start" || e.type === "login_success") &&
    !ctx.guests.has(e.session_id)
  ) {
    const name =
      e.type === "session_start" && e.detail.guest_name?.trim()
        ? e.detail.guest_name.trim()
        : "A judge";
    const via = e.protocol === "http" ? "the web" : "SSH";
    return {
      fantasy: `A guest knight approaches from ${placeOf(e.geo)}`,
      plain: `${name} connected over ${via} at our table`,
      tone: "guest",
    };
  }
  const c = creatureOf(e.attacker);
  if (e.type === "tripwire") {
    return {
      fantasy: `Hear ye! A ${c.name.toLowerCase()} from ${placeOf(e.geo)} fell for the tripwire`,
      plain:
        e.attacker.kind === "agent"
          ? "AI agent read a hidden note meant only for AI"
          : `A ${c.kind} touched a hidden decoy file`,
      tone: "danger",
    };
  }
  if (e.attacker.threat === "critical" && !ctx.dragons.has(who(e))) {
    return {
      fantasy: "A dragon circles the castle!",
      plain: `A ${c.kind} from ${placeOf(e.geo)} reached critical threat`,
      tone: "danger",
    };
  }
  if (e.type === "dossier") {
    return {
      fantasy: "The oracle has spoken",
      plain: `Web reputation lookup returned ${e.attacker.reputation}`,
      tone: "oracle",
    };
  }
  const country = countryName(e.geo.country);
  if (
    country &&
    e.source !== "guest" &&
    e.source !== "team" &&
    !ctx.countries.has(e.geo.country)
  ) {
    return {
      fantasy: `A stranger arrives from ${country}!`,
      plain: `First visitor from ${country} today`,
      tone: "news",
    };
  }
  return null;
}

// marks the event as announced so the same thing never heralds twice
export function remember(e: AttackEvent, ctx: HeraldCtx) {
  if (e.source === "guest") ctx.guests.add(e.session_id);
  if (e.attacker.threat === "critical") ctx.dragons.add(who(e));
  if (e.geo.country && e.geo.country !== "XX" && e.source !== "guest")
    ctx.countries.add(e.geo.country);
}

export type Queued = Herald & { id: string };
const MAX = 3;

// keeps at most MAX, never drops a guest; a newer non-guest waits its turn or is dropped
export function enqueue(q: Queued[], h: Queued): Queued[] {
  if (q.some((x) => x.id === h.id)) return q;
  if (q.length < MAX) return [...q, h];
  if (h.tone !== "guest") return q;
  let drop = -1;
  for (let i = q.length - 1; i > 0; i--)
    if (q[i].tone !== "guest") {
      drop = i;
      break;
    }
  if (drop < 0) return [...q, h];
  return [...q.slice(0, drop), ...q.slice(drop + 1), h];
}
