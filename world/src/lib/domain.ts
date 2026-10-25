import type {
  AttackEvent,
  AttackerSummary,
  SessionSummary,
  Stats,
  Threat,
  AttackerProfile,
} from "./contracts";
export const emptyStats: Stats = {
  total_sessions: 0,
  active_now: 0,
  countries: 0,
  breaches: 0,
  by_kind: { bot: 0, human: 0, agent: 0, unknown: 0 },
  by_reputation: { harmless: 0, unknown: 0, malicious: 0 },
  per_minute: [],
};
export interface Domain {
  events: Record<string, AttackEvent>;
  recent: string[];
  sessions: Record<string, SessionSummary>;
  attackers: Record<string, AttackerSummary>;
  stats: Stats;
}
export const emptyDomain = (): Domain => ({
  events: {},
  recent: [],
  sessions: {},
  attackers: {},
  stats: emptyStats,
});
export const ranks: Record<Threat, number> = {
  low: 0,
  med: 1,
  high: 2,
  critical: 3,
};
export const eventOrder = (a: AttackEvent, b: AttackEvent) =>
  a.timestamp.localeCompare(b.timestamp) ||
  a.event_id.localeCompare(b.event_id);
export function ingest(state: Domain, event: AttackEvent): Domain {
  if (state.events[event.event_id]) return state;
  const events = { ...state.events, [event.event_id]: event };
  const history = Object.values(events)
    .filter((e) => e.session_id === event.session_id)
    .sort(eventOrder);
  const first = history[0],
    last = history.at(-1)!;
  const ended = history.findLast((e) => e.type === "session_end");
  const prior = state.sessions[event.session_id];
  const session: SessionSummary = {
    session_id: event.session_id,
    started_at:
      prior && prior.started_at < first.timestamp
        ? prior.started_at
        : first.timestamp,
    ended_at: ended?.timestamp ?? prior?.ended_at ?? null,
    source: last.source,
    geo: last.geo,
    attacker: last.attacker,
    status:
      ended || prior?.ended_at
        ? "ended"
        : history.some((e) => e.type === "login_success")
          ? "inside"
          : history.some((e) => e.type === "login_fail")
            ? "at_gate"
            : (prior?.status ?? "approaching"),
    login_fails: history.filter((e) => e.type === "login_fail").length,
    command_count:
      ended?.type === "session_end"
        ? ended.detail.command_count
        : history.filter((e) => e.type === "command").length,
    story:
      history.findLast((e) => e.type === "story")?.detail.story ??
      prior?.story ??
      null,
  };
  const sessions = { ...state.sessions, [session.session_id]: session };
  const attackers = { ...state.attackers };
  const key = event.attacker.ip_hash;
  if (key) {
    const visits = Object.values(sessions)
      .filter((s) => s.attacker.ip_hash === key)
      .sort((a, b) => b.started_at.localeCompare(a.started_at));
    const all = Object.values(events)
      .filter((e) => e.attacker.ip_hash === key)
      .sort(eventOrder);
    const latest = all.at(-1)!;
    const classified = all.findLast((e) => e.attacker.kind !== "unknown");
    const old = attackers[key];
    const profile = latest.attacker;
    const maxThreat = all.reduce<Threat>(
      (max, e) =>
        ranks[e.attacker.threat] > ranks[max] ? e.attacker.threat : max,
      old?.max_threat ?? "low",
    );
    attackers[key] = {
      ip_hash: key,
      visits: Math.max(old?.visits ?? 0, visits.length),
      first_seen: visits.at(-1)!.started_at,
      last_seen: latest.timestamp,
      latest_session_id: latest.session_id,
      source: latest.source,
      geo: latest.geo,
      attacker: {
        kind: classified?.attacker.kind ?? old?.attacker.kind ?? profile.kind,
        confidence:
          classified?.attacker.confidence ??
          old?.attacker.confidence ??
          profile.confidence,
        reputation: profile.reputation,
        family: profile.family,
        threat: profile.threat,
      },
      max_threat: maxThreat,
      session_ids: visits.map((s) => s.session_id).slice(0, 50),
    };
  }
  const recent = Object.values(events)
    .sort(eventOrder)
    .slice(-100)
    .reverse()
    .map((e) => e.event_id);
  // keep replay in the adapter; retain bounded local history for projections.
  const keep = Object.values(events).sort(eventOrder).slice(-2000);
  return {
    ...state,
    events: Object.fromEntries(keep.map((e) => [e.event_id, e])),
    recent,
    sessions,
    attackers,
  };
}
export function appearance(a: AttackerProfile, max: Threat = a.threat) {
  if (max === "critical")
    return { name: "Dragon", variant: "dragon", color: "#ad392b" };
  const color = {
    bot: "#527845",
    human: "#287dd0",
    agent: "#8257a6",
    unknown: "#64656a",
  }[a.kind];
  if (a.kind === "unknown") return { name: "Shadow", variant: "shadow", color };
  if (a.reputation === "harmless")
    return { name: "Slime", variant: "slime", color };
  const elite = a.reputation === "malicious";
  return {
    name: {
      bot: elite ? "Stone golem" : "Clay golem",
      human: elite ? "Evil witch" : "Dark mage",
      agent: elite ? "Cursed fae" : "Fae",
    }[a.kind],
    variant: elite ? "elite" : "base",
    color,
  };
}
export function activeVisits(state: Domain, key: string) {
  return Object.values(state.sessions).filter(
    (s) => s.attacker.ip_hash === key && s.status !== "ended",
  ).length;
}
export function parseTransport(json: string): AttackEvent | null {
  let message;
  try {
    message = JSON.parse(json);
  } catch {
    return null;
  }
  if (message?.type === "ping") return null;
  if (
    !message ||
    ![
      "session_start",
      "login_fail",
      "login_success",
      "command",
      "tripwire",
      "classified",
      "dossier",
      "story",
      "session_end",
    ].includes(message.type) ||
    typeof message.event_id !== "string" ||
    typeof message.session_id !== "string" ||
    typeof message.timestamp !== "string" ||
    !message.geo ||
    !message.attacker ||
    !message.detail
  )
    return null;
  return message as AttackEvent;
}
export function eventText(e: AttackEvent): string {
  switch (e.type) {
    case "session_start":
      return "Approaching the gate";
    case "login_fail":
      return `Tried ${e.detail.username}`;
    case "login_success":
      return "Entered the simulated fortress";
    case "command":
      return `Ran ${e.detail.command}`;
    case "tripwire":
      return "Hit a tripwire";
    case "classified":
      return "Classification updated";
    case "dossier":
      return "Dossier received";
    case "story":
      return "Encounter recorded";
    case "session_end":
      return "Visit ended";
  }
}
export const location = (geo: SessionSummary["geo"]) =>
  `${geo.city ?? "Unknown city"}, ${geo.country === "XX" ? "Unknown country" : (new Intl.DisplayNames(["en"], { type: "region" }).of(geo.country) ?? geo.country)}`;
