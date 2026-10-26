// turns picked raw sessions into the public snapshot: new ids, only the fields
// the ui reads, rounded geo and scrubbed text
import { randomBytes, randomUUID } from "node:crypto";
import type {
  AttackEvent,
  AttackerSummary,
  SessionResponse,
  Stats,
} from "../../src/lib/contracts";
import type { ReplaySnapshot } from "../../src/lib/replay";
import { newIpMap, scrubText, scrubUrl } from "./scrub";

export interface RawDump {
  fetched_at: string;
  stats: Stats;
  attackers: AttackerSummary[];
  sessions: SessionResponse[];
}

const hex = (n: number) =>
  randomBytes(Math.ceil(n / 2))
    .toString("hex")
    .slice(0, n);
// lap 0 ids end in 0000; the replay rewrites that tail per lap
const eventId = () => randomUUID().slice(0, 32) + "0000";
const sessionId = () => hex(28) + "0000";
const round2 = (x: number) => Math.round(x * 100) / 100;

export function anonymize(
  dump: RawDump,
  picked: SessionResponse[],
): ReplaySnapshot {
  const ips = newIpMap();
  const text = (s: string) => scrubText(s, ips);
  const hashes = new Map<string, string>();
  // guests and team runs all share our table's ip, so each visit is its own creature
  const rekey = (e: AttackEvent) => {
    if (!e.attacker.ip_hash) return null;
    const k =
      e.source === "wild" ? e.attacker.ip_hash : `${e.source}:${e.session_id}`;
    if (!hashes.has(k)) hashes.set(k, hex(64));
    return hashes.get(k)!;
  };
  const sessions = new Map<string, string>();

  const clean = (e: AttackEvent): AttackEvent => {
    if (!sessions.has(e.session_id)) sessions.set(e.session_id, sessionId());
    const base = {
      event_id: eventId(),
      session_id: sessions.get(e.session_id)!,
      timestamp: e.timestamp,
      source: e.source,
      protocol: e.protocol,
      geo: {
        lat: round2(e.geo.lat),
        lon: round2(e.geo.lon),
        country: e.geo.country,
        city: e.geo.city,
      },
      attacker: {
        kind: e.attacker.kind,
        confidence: e.attacker.confidence,
        reputation: e.attacker.reputation,
        family: e.attacker.family ? text(e.attacker.family) : null,
        threat: e.attacker.threat,
        client: e.attacker.client ? text(e.attacker.client) : null,
        ip_hash: rekey(e),
      },
    };
    switch (e.type) {
      case "session_start":
        // guest names belong to real people at our table
        return { ...base, type: e.type, detail: {} };
      case "login_fail":
      case "login_success":
        return {
          ...base,
          type: e.type,
          detail: { username: text(e.detail.username).slice(0, 256) },
        };
      case "command":
        return {
          ...base,
          type: e.type,
          detail: {
            command: text(e.detail.command),
            output: text(e.detail.output).slice(0, 500),
            response_ms: Math.round(e.detail.response_ms),
            answered_by: e.detail.answered_by,
            techniques: e.detail.techniques,
          },
        };
      case "tripwire":
        return {
          ...base,
          type: e.type,
          detail: {
            tripwire_id: e.detail.tripwire_id,
            reasons: e.detail.reasons.map(text),
          },
        };
      case "classified":
        return {
          ...base,
          type: e.type,
          detail: { reasons: e.detail.reasons.map(text) },
        };
      case "dossier": {
        const seen = new Set<string>();
        const sources = [];
        for (const s of e.detail.sources) {
          const url = scrubUrl(s.url);
          if (!url || seen.has(url)) continue;
          seen.add(url);
          // lookup ids in titles can lead back to the visitor
          sources.push({ title: text(s.title).replace(/\d{5,}/g, "…"), url });
        }
        return {
          ...base,
          type: e.type,
          detail: { summary: text(e.detail.summary), sources },
        };
      }
      case "story":
        return {
          ...base,
          type: e.type,
          detail: { story: text(e.detail.story) },
        };
      case "session_end":
        return {
          ...base,
          type: e.type,
          detail: {
            duration_s: Math.round(e.detail.duration_s * 10) / 10,
            command_count: e.detail.command_count,
          },
        };
    }
  };

  // keep each session's own order, then interleave by time (stable sort)
  const events = picked
    .flatMap((s) => s.events.map(clean))
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const recorded = new Map(
    dump.attackers
      .filter((a) => a.source === "wild")
      .map((a) => [a.ip_hash, a.visits]),
  );
  const visits: Record<string, number> = {};
  for (const [old, id] of hashes)
    visits[id] = old.includes(":")
      ? 1
      : (recorded.get(old) ??
        dump.sessions.filter((s) => s.session.attacker.ip_hash === old).length);

  return {
    version: 1,
    recorded: { from: events[0].timestamp, to: events.at(-1)!.timestamp },
    stats: dump.stats,
    visits,
    events,
  };
}
