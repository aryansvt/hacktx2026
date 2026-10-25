import { create } from "zustand";
import type {
  AttackEvent,
  AttackerSummary,
  DataAdapter,
  SessionResponse,
  SessionSummary,
  Snapshot,
  Stats,
} from "./contracts";
import { emptyStats, parseTransport } from "./domain";

export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "https://api.followthebreadcrumbs.tech"
).replace(/\/$/, "");
export const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL ?? "wss://api.followthebreadcrumbs.tech/live";

export type Conn = "connecting" | "live" | "reconnecting" | "offline";
export const useConn = create<{ conn: Conn; set: (c: Conn) => void }>(
  (set) => ({ conn: "connecting", set: (conn) => set({ conn }) }),
);

// backoff: 1, 2, 4, 8, then 10s max
export const backoff = (attempt: number) =>
  Math.min(10_000, 1000 * 2 ** Math.max(0, attempt));

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json() as Promise<T>;
}

export const fetchStats = () => get<Stats>("/stats");

export function createLiveAdapter(): DataAdapter {
  let ws: WebSocket | null = null;
  let closed = false;
  let attempt = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let listener: ((e: AttackEvent) => void) | null = null;
  // events that land before the snapshot is in
  const buffer: AttackEvent[] = [];
  const setConn = (c: Conn) => useConn.getState().set(c);

  const open = () => {
    if (closed) return;
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
      attempt = 0;
      setConn("live");
    };
    ws.onmessage = (m) => {
      const e = parseTransport(String(m.data));
      if (!e) return;
      if (listener) listener(e);
      else buffer.push(e);
    };
    ws.onclose = () => {
      if (closed) return;
      setConn("reconnecting");
      timer = setTimeout(open, backoff(attempt++));
    };
    ws.onerror = () => ws?.close();
  };
  open();

  return {
    mode: "live",
    async snapshot(): Promise<Snapshot> {
      const [attackers, sessions, stats] = await Promise.all([
        get<AttackerSummary[]>("/attackers?limit=100"),
        get<SessionSummary[]>("/sessions?limit=50"),
        get<Stats>("/stats").catch(() => emptyStats),
      ]);
      return { attackers, sessions, stats, events: [] };
    },
    session: (id) =>
      get<SessionResponse>(`/sessions/${encodeURIComponent(id)}`),
    subscribe(onEvent) {
      listener = onEvent;
      for (const e of buffer.splice(0)) onEvent(e);
      return () => {
        listener = null;
      };
    },
    close() {
      closed = true;
      clearTimeout(timer);
      ws?.close();
    },
  };
}
