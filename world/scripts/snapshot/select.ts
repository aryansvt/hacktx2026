// picks the most interesting whole sessions for the replay, within an event budget
import type { SessionResponse, Threat } from "../../src/lib/contracts";
import { variantOf } from "../../src/lib/creatures";

const rank: Record<Threat, number> = { low: 0, med: 1, high: 2, critical: 3 };
// noisy scanners connected hundreds of times; a few visits tell the story
const PER_ATTACKER = 3;
const TEAM_MAX = 10;
// long scripted scans eat the budget without showing anything new
const LONG = 60;

function profile(s: SessionResponse) {
  const last = s.events.at(-1)?.attacker ?? s.session.attacker;
  const max = s.events.reduce<Threat>(
    (m, e) => (rank[e.attacker.threat] > rank[m] ? e.attacker.threat : m),
    "low",
  );
  return { last, max };
}

export function score(s: SessionResponse): number {
  const { last, max } = profile(s);
  const has = (t: string) => s.events.some((e) => e.type === t);
  const commands = s.events.filter((e) => e.type === "command");
  let n = 0;
  if (max === "critical") n += 100;
  if (s.session.source === "guest") n += 80;
  if (last.reputation === "harmless") n += 60;
  if (last.kind === "agent") n += 60;
  if (last.reputation === "malicious") n += 50;
  if (last.family) n += 30;
  if (s.session.source === "team") n += 25;
  if (has("dossier")) n += 15;
  if (has("tripwire")) n += 15;
  if (commands.some((e) => e.type === "command" && e.detail.answered_by === "llm"))
    n += 10;
  if (has("login_success")) n += 8;
  return n + Math.min(commands.length, 10);
}

export function selectSessions(
  sessions: SessionResponse[],
  budget: number,
): SessionResponse[] {
  const ended = sessions.filter((s) =>
    s.events.some((e) => e.type === "session_end"),
  );
  const ranked = ended
    .map((s) => ({ s, score: score(s) }))
    .sort(
      (a, b) =>
        b.score - a.score ||
        a.s.session.started_at.localeCompare(b.s.session.started_at),
    );
  const picked = new Set<SessionResponse>();
  const perAttacker = new Map<string, number>();
  const countries = new Set<string>();
  let used = 0,
    team = 0;
  // people at our table share one ip, so each of their visits counts on its own
  const who = (s: SessionResponse) =>
    s.session.source === "wild"
      ? (s.session.attacker.ip_hash ?? s.session.session_id)
      : s.session.session_id;
  const take = (s: SessionResponse) => {
    picked.add(s);
    used += s.events.length;
    perAttacker.set(who(s), (perAttacker.get(who(s)) ?? 0) + 1);
    countries.add(s.session.geo.country);
    if (s.session.source === "team") team++;
  };
  const fits = (s: SessionResponse) =>
    !picked.has(s) &&
    used + s.events.length <= budget &&
    (s.session.source !== "team" || team < TEAM_MAX);

  // the stars: dragons, guests, slimes and fae, whatever the budget
  for (const { s, score } of ranked)
    if (score >= 60 && s.session.source !== "team") take(s);
  // our own runs: take turns across creature types so fae aren't crowded out by dragons
  const byVariant = new Map<string, SessionResponse[]>();
  for (const { s } of ranked)
    if (s.session.source === "team") {
      const { last, max } = profile(s);
      const v = variantOf(last, max);
      byVariant.set(v, [...(byVariant.get(v) ?? []), s]);
    }
  for (let round = 0; team < TEAM_MAX; round++) {
    const next = [...byVariant.values()].map((l) => l[round]).filter(Boolean);
    if (!next.length) break;
    for (const s of next) if (fits(s)) take(s);
  }
  // every country that showed up gets at least one visit
  for (const { s } of ranked)
    if (!countries.has(s.session.geo.country) && s.events.length <= LONG)
      take(s);
  // then one visit per attacker, then a few more, best first
  for (const cap of [1, PER_ATTACKER])
    for (const { s, score } of ranked)
      if (
        fits(s) &&
        (perAttacker.get(who(s)) ?? 0) < cap &&
        (s.events.length <= LONG || score >= 50)
      )
        take(s);
  return [...picked];
}
