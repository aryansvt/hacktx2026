import type {
  AttackEvent,
  Attacker,
  DataAdapter,
  DetailMap,
  Geo,
  Snapshot,
  SessionResponse,
} from "./contracts";
import { emptyDomain, ingest, parseTransport } from "./domain";
const epoch = Date.parse("2026-10-25T12:00:00Z");
const places: Geo[] = [
  { lat: 52.37, lon: 4.9, city: "Amsterdam", country: "NL" },
  { lat: 1.35, lon: 103.82, city: "Singapore", country: "SG" },
  { lat: 30.27, lon: -97.74, city: "Austin", country: "US" },
  { lat: 50.11, lon: 8.68, city: "Frankfurt", country: "DE" },
  { lat: 35.68, lon: 139.69, city: "Tokyo", country: "JP" },
  { lat: -23.55, lon: -46.63, city: "São Paulo", country: "BR" },
  { lat: 51.51, lon: -0.13, city: "London", country: "GB" },
];
const kinds: Attacker["kind"][] = [
  "bot",
  "agent",
  "human",
  "unknown",
  "bot",
  "human",
  "agent",
];
export function fixtureEvent<T extends keyof DetailMap>(
  i: number,
  visit: string,
  type: T,
  detail: DetailMap[T],
  n: number,
): AttackEvent {
  const attacker: Attacker = {
    kind: kinds[i],
    confidence: i === 3 ? 0 : 0.91,
    reputation:
      i === 0 || i === 1 ? "malicious" : i === 4 ? "harmless" : "unknown",
    family: i === 0 ? "Mirai" : null,
    threat: i === 5 ? "critical" : i === 0 || i === 1 ? "high" : "low",
    client: i === 1 ? "Fixture HTTP client" : "SSH-2.0-Go",
    ip_hash: (i + 1).toString(16).repeat(64),
  };
  return {
    event_id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    session_id: visit,
    type,
    timestamp: new Date(epoch + n * 1000).toISOString(),
    source: "mock",
    protocol: i === 1 ? "http" : "ssh",
    geo: places[i],
    attacker,
    detail,
  } as AttackEvent;
}
export function fixtures() {
  const events: AttackEvent[] = [];
  let n = 0;
  for (let i = 0; i < 7; i++) {
    const id = `fixture-visit-${i + 1}`;
    const add = <T extends keyof DetailMap>(type: T, detail: DetailMap[T]) =>
      events.push(fixtureEvent(i, id, type, detail, ++n));
    add("session_start", {});
    if (i === 3) {
      add("login_fail", { username: "root" });
      add("session_end", { duration_s: 2, command_count: 0 });
      continue;
    }
    add("classified", {
      reasons:
        i === 0
          ? ["burst timing", "repeated login failures"]
          : i === 1
            ? ["tripwire hit", "command pattern"]
            : ["observed command timing"],
    });
    add("login_fail", { username: "root" });
    add("login_success", { username: "root" });
    add("command", {
      command: i === 1 ? "GET /admin" : "whoami",
      output: i === 1 ? "Simulated admin page" : "root",
      response_ms: 24,
      answered_by: "engine",
      techniques: ["T1033"],
    });
    if (i === 1)
      add("tripwire", {
        tripwire_id: "fixture-admin",
        reasons: ["tripwire hit"],
      });
    add("dossier", {
      summary:
        "Synthetic evidence for this demonstration. No real visitor is described.",
      sources: [
        {
          title: "MITRE: System Owner/User Discovery",
          url: "https://attack.mitre.org/techniques/T1033/",
        },
      ],
    });
    add("story", {
      story: "A fixture visitor approached the research fortress.",
    });
  }
  events.push(fixtureEvent(0, "fixture-overlap", "session_start", {}, ++n));
  events.push(
    fixtureEvent(
      0,
      "fixture-visit-1",
      "session_end",
      { duration_s: 43, command_count: 1 },
      ++n,
    ),
  );
  return events;
}
export function createMockAdapter(): DataAdapter {
  let events = fixtures();
  let state = events.reduce(ingest, emptyDomain());
  let timer: ReturnType<typeof setInterval> | undefined;
  const snapshot = async (): Promise<Snapshot> => ({
    events: [...events],
    sessions: Object.values(state.sessions),
    attackers: Object.values(state.attackers),
    stats: state.stats,
  });
  return {
    mode: "mock",
    snapshot,
    async session(id): Promise<SessionResponse> {
      const session = state.sessions[id];
      if (!session) throw new Error("This fixture visit is unavailable.");
      return {
        session,
        events: events
          .filter((e) => e.session_id === id)
          .sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
      };
    },
    subscribe(listener) {
      let tick = 0;
      timer = setInterval(() => {
        const ping = parseTransport('{"type":"ping"}');
        if (ping) listener(ping);
        if (tick >= 56) return;
        const i = Math.floor(tick / 4) % 7,
          phase = tick % 4,
          id = `fixture-stream-${Math.floor(tick / 4)}`;
        const e =
          phase === 0
            ? fixtureEvent(i, id, "session_start", {}, 100 + tick)
            : phase === 1
              ? fixtureEvent(
                  i,
                  id,
                  "classified",
                  { reasons: ["fixture behavior sample"] },
                  100 + tick,
                )
              : phase === 2
                ? fixtureEvent(
                    i,
                    id,
                    "login_fail",
                    { username: "admin" },
                    100 + tick,
                  )
                : fixtureEvent(
                    i,
                    id,
                    "session_end",
                    { duration_s: 12, command_count: 0 },
                    100 + tick,
                  );
        events = [...events, e];
        state = ingest(state, e);
        listener(e);
        tick++;
      }, 4000);
      return () => {
        clearInterval(timer);
      };
    },
    close() {
      clearInterval(timer);
    },
  };
}
// live is deliberately unavailable until M5, even when configured with "0".
export const mockRequested = (value: string | undefined) =>
  value === undefined || value === "1";
