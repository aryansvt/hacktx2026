import type {
  AdapterControl,
  AttackEvent,
  AttackerSummary,
  DataAdapter,
  Snapshot,
  Source,
  Stats,
  Threat,
} from "./contracts";
import { creatureKey, emptyDomain, ingest, ranks } from "./domain";

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

// pacing: a lap of about 12 minutes, recorded gaps squeezed between these bounds
const TARGET_MS = 12 * 60_000;
const LEAD_MS = 1500;
const TAIL_MS = 5000;
const MIN_GAP = 800;
const MAX_GAP = 12_000;
// longest pause inside one visit
const MAX_INSIDE = 4000;

export interface Schedule {
  lapMs: number;
  items: { at: number; event: AttackEvent }[];
  // per session (lap 0 id): when it starts and ends within a lap
  sessions: Record<string, { start: number; end: number; source: Source }>;
}

export function buildSchedule(
  events: AttackEvent[],
  targetMs = TARGET_MS,
): Schedule {
  const groups = new Map<string, AttackEvent[]>();
  for (const e of events) {
    const g = groups.get(e.session_id);
    if (g) g.push(e);
    else groups.set(e.session_id, [e]);
  }
  const visits = [...groups.values()]
    .map((list) => {
      const t = list.map((e) => Date.parse(e.timestamp));
      const rel = [0];
      for (let i = 1; i < list.length; i++)
        rel.push(
          rel[i - 1] + Math.min(Math.max(0, t[i] - t[i - 1]), MAX_INSIDE),
        );
      const ended = list.findIndex((e) => e.type === "session_end");
      return {
        list,
        start: t[0],
        rel,
        end: ended >= 0 ? rel[ended] : rel.at(-1)!,
      };
    })
    .sort((a, b) => a.start - b.start);
  if (!visits.length) return { lapMs: TAIL_MS, items: [], sessions: {} };

  const gaps = visits.slice(1).map((v, i) => v.start - visits[i].start);
  const place = (scale: number) => {
    const at = [LEAD_MS];
    for (const g of gaps)
      at.push(at.at(-1)! + Math.min(MAX_GAP, Math.max(MIN_GAP, g * scale)));
    return at;
  };
  const length = (at: number[]) =>
    Math.max(...visits.map((v, i) => at[i] + v.rel.at(-1)!)) + TAIL_MS;
  // find the scale that lands the lap near the target
  let lo = 0,
    hi = 1;
  while (length(place(hi)) < targetMs && hi < 1e6) hi *= 2;
  for (let i = 0; i < 40; i++) {
    const mid = (lo + hi) / 2;
    if (length(place(mid)) < targetMs) lo = mid;
    else hi = mid;
  }
  const at = place(length(place(0)) >= targetMs ? 0 : hi);

  const items: Schedule["items"] = [];
  const sessions: Schedule["sessions"] = {};
  visits.forEach((v, i) => {
    v.list.forEach((event, j) =>
      items.push({ at: Math.round(at[i] + v.rel[j]), event }),
    );
    sessions[v.list[0].session_id] = {
      start: Math.round(at[i]),
      end: Math.round(at[i] + v.end),
      source: v.list[0].source,
    };
  });
  // stable, so ties keep their recorded order
  items.sort((a, b) => a.at - b.at);
  return { lapMs: Math.round(length(at)), items, sessions };
}

// snapshot ids end in 0000; each lap gets its own tail so laps never collide
export const lapId = (id: string, lap: number) =>
  id.slice(0, -4) + (lap & 0xffff).toString(16).padStart(4, "0");

// one attacker summary per creature, as the domain would build it
function summarize(
  events: AttackEvent[],
  visits: Record<string, number>,
): AttackerSummary[] {
  const by = new Map<string, AttackEvent[]>();
  for (const e of events) {
    const key = creatureKey(e);
    const list = by.get(key);
    if (list) list.push(e);
    else by.set(key, [e]);
  }
  return [...by].map(([key, list]) => {
    const last = list.at(-1)!;
    const known = list.findLast((e) => e.attacker.kind !== "unknown") ?? last;
    const ids = [...new Set(list.map((e) => e.session_id))].reverse();
    return {
      ip_hash: key,
      visits: visits[key] ?? ids.length,
      first_seen: list[0].timestamp,
      last_seen: last.timestamp,
      latest_session_id: last.session_id,
      source: last.source,
      geo: last.geo,
      attacker: {
        kind: known.attacker.kind,
        confidence: known.attacker.confidence,
        reputation: last.attacker.reputation,
        family: last.attacker.family,
        threat: last.attacker.threat,
      },
      max_threat: list.reduce<Threat>(
        (m, e) => (ranks[e.attacker.threat] > ranks[m] ? e.attacker.threat : m),
        "low",
      ),
      session_ids: ids.slice(0, 50),
    };
  });
}

export function createReplayAdapter(
  opts: {
    url?: string;
    load?: () => Promise<ReplaySnapshot>;
    targetMs?: number;
  } = {},
): DataAdapter {
  const load =
    opts.load ??
    (async () => {
      const res = await fetch(opts.url ?? "/replay/snapshot.json");
      if (!res.ok) throw new Error(`replay snapshot returned ${res.status}`);
      return (await res.json()) as ReplaySnapshot;
    });
  let data: ReplaySnapshot | null = null;
  let sched: Schedule | null = null;
  const bySession = new Map<string, Schedule["items"]>();
  // wall time of the replay's zero, pushed forward while the tab is hidden
  let origin = 0;
  let lap = 1;
  let cursor = 0;
  let active = -1;
  let lastTick = 0;
  let hiddenAt: number | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let emit: ((e: AttackEvent) => void) | null = null;
  let control: AdapterControl = {};
  const doc = () => (typeof document === "undefined" ? null : document);

  const lapStart = (k: number) => origin + (k - 1) * sched!.lapMs;
  const pos = () => Date.now() - lapStart(lap);
  const stamp = (item: Schedule["items"][number], k: number) =>
    ({
      ...item.event,
      event_id: lapId(item.event.event_id, k),
      session_id: lapId(item.event.session_id, k),
      timestamp: new Date(lapStart(k) + item.at).toISOString(),
    }) as AttackEvent;

  const stats = (): Stats => {
    const s = data!.stats;
    const p = pos();
    const activeNow = Object.values(sched!.sessions).filter(
      (v) => v.source === "wild" && v.start <= p && p < v.end,
    ).length;
    // the recorded per-minute history, shifted so it ends now
    const last = s.per_minute.at(-1);
    const shift = last
      ? Math.floor(Date.now() / 60_000) * 60_000 - Date.parse(last.t)
      : 0;
    return {
      ...s,
      active_now: activeNow,
      per_minute: s.per_minute.map((m) => ({
        ...m,
        t: new Date(Date.parse(m.t) + shift).toISOString(),
      })),
    };
  };
  // every creature as of the previous lap, no visits in progress
  const base = (k: number): Snapshot => ({
    attackers: summarize(
      sched!.items.map((i) => stamp(i, k - 1)),
      data!.visits,
    ),
    sessions: [],
    events: [],
    stats: stats(),
  });

  const tick = () => {
    clearTimeout(timer);
    if (!sched || !emit || hiddenAt !== null) return;
    // a sleeping laptop counts as a pause, not a backlog
    const wall = Date.now();
    if (lastTick && wall - lastTick > 5000) origin += wall - lastTick - 1000;
    lastTick = wall;
    let p = pos();
    for (;;) {
      while (cursor < sched.items.length && sched.items[cursor].at <= p)
        emit(stamp(sched.items[cursor++], lap));
      if (p < sched.lapMs) break;
      lap++;
      cursor = 0;
      p = pos();
      control.reset?.(base(lap));
    }
    const now = stats();
    if (now.active_now !== active) {
      active = now.active_now;
      control.stats?.(now);
    }
    const next =
      cursor < sched.items.length ? sched.items[cursor].at : sched.lapMs;
    timer = setTimeout(tick, Math.min(1000, Math.max(16, next - p)));
  };

  const onVisibility = () => {
    if (doc()?.hidden) {
      hiddenAt ??= Date.now();
      clearTimeout(timer);
    } else if (hiddenAt !== null) {
      origin += Date.now() - hiddenAt;
      hiddenAt = null;
      lastTick = Date.now();
      tick();
    }
  };
  const stop = () => {
    emit = null;
    clearTimeout(timer);
    doc()?.removeEventListener("visibilitychange", onVisibility);
  };

  return {
    mode: "replay",
    async snapshot() {
      data = await load();
      sched = buildSchedule(data.events, opts.targetMs);
      bySession.clear();
      for (const item of sched.items) {
        const list = bySession.get(item.event.session_id);
        if (list) list.push(item);
        else bySession.set(item.event.session_id, [item]);
      }
      origin = Date.now();
      lap = 1;
      cursor = 0;
      return base(1);
    },
    async session(id) {
      if (!sched) throw new Error("The replay is still loading.");
      const tail = parseInt(id.slice(-4), 16);
      // the latest lap with this tail
      const k = lap - ((lap - tail) & 0xffff);
      const items = bySession.get(lapId(id, 0)) ?? [];
      const played = k < lap ? items : items.filter((i) => i.at <= pos());
      if (Number.isNaN(tail) || k < 0 || !played.length)
        throw new Error("This visit hasn't happened yet.");
      const events = played.map((i) => stamp(i, k));
      const state = events.reduce(ingest, emptyDomain());
      return { session: state.sessions[events[0].session_id], events };
    },
    subscribe(onEvent, ctrl = {}) {
      emit = onEvent;
      control = ctrl;
      active = -1;
      lastTick = 0;
      const d = doc();
      if (d) {
        d.addEventListener("visibilitychange", onVisibility);
        if (d.hidden) hiddenAt = Date.now();
      }
      tick();
      return stop;
    },
    close: stop,
  };
}
