import type { AttackEvent, Threat } from "../../lib/contracts";

// pure helpers for the creature page and the oracle

export const GAP_CAP_MS = 2500;
export const GAP_MIN_MS = 250;

// event types that show up in the terminal replay
const replayable = new Set<AttackEvent["type"]>([
  "session_start",
  "login_fail",
  "login_success",
  "command",
  "tripwire",
  "session_end",
]);

export const replayEvents = (events: AttackEvent[]) =>
  events.filter((e) => replayable.has(e.type));

// real delay before each event, capped so long idle gaps don't stall
export function replayGaps(
  events: { timestamp: string }[],
  cap = GAP_CAP_MS,
  min = GAP_MIN_MS,
): number[] {
  return events.map((e, i) => {
    if (i === 0) return 0;
    const raw = Date.parse(e.timestamp) - Date.parse(events[i - 1].timestamp);
    if (!Number.isFinite(raw)) return min;
    return Math.min(cap, Math.max(min, raw));
  });
}

export function domainOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url.replace(/^[a-z]+:\/\//i, "").split("/")[0] || url;
  }
}

// reasons from the latest classified event, falling back to tripwire reasons
export function reasonsOf(events: AttackEvent[]): string[] {
  const last = events.findLast((e) => e.type === "classified");
  if (last?.type === "classified" && last.detail.reasons.length)
    return [...new Set(last.detail.reasons)];
  const trips = events.flatMap((e) =>
    e.type === "tripwire" ? e.detail.reasons : [],
  );
  return [...new Set(trips)];
}

export function latestOf<T extends AttackEvent["type"]>(
  events: AttackEvent[],
  type: T,
): Extract<AttackEvent, { type: T }> | undefined {
  return events.findLast((e) => e.type === type) as
    Extract<AttackEvent, { type: T }> | undefined;
}

export function relativeTime(iso: string, now: number): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "unknown";
  const s = Math.round((now - t) / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}

export interface Line {
  id: string;
  tone: "muted" | "fail" | "ok" | "cmd" | "trip" | "end";
  text: string;
  output?: string;
  tag?: string;
}

// one terminal line per replayable event, never with passwords
export function lineOf(e: AttackEvent): Line | null {
  const id = e.event_id;
  switch (e.type) {
    case "session_start":
      return {
        id,
        tone: "muted",
        text: e.detail.guest_name
          ? `${e.detail.guest_name} connected over ${e.protocol}`
          : `connected over ${e.protocol}`,
      };
    case "login_fail":
      return { id, tone: "fail", text: `login as ${e.detail.username} failed` };
    case "login_success":
      return { id, tone: "ok", text: `login as ${e.detail.username} accepted` };
    case "command":
      return {
        id,
        tone: "cmd",
        text: e.detail.command,
        output: e.detail.output,
        tag: e.detail.answered_by,
      };
    case "tripwire":
      return {
        id,
        tone: "trip",
        text: `tripwire: ${e.detail.tripwire_id}`,
        output: e.detail.reasons.join("; ") || undefined,
      };
    case "session_end":
      return {
        id,
        tone: "end",
        text: `session closed after ${Math.round(e.detail.duration_s)}s, ${e.detail.command_count} command${e.detail.command_count === 1 ? "" : "s"}`,
      };
    default:
      return null;
  }
}

export const verdictLabel = {
  malicious: "Malicious",
  harmless: "Harmless",
  unknown: "Unknown",
} as const;

// small bounded queue: drop the oldest when full
export function enqueue<T>(queue: T[], item: T, cap = 3): T[] {
  const next = [...queue, item];
  return next.length > cap ? next.slice(next.length - cap) : next;
}

export const threatColor: Record<Threat, string> = {
  low: "var(--threat-low)",
  med: "var(--threat-med)",
  high: "var(--threat-high)",
  critical: "var(--threat-critical)",
};
export const verdictColor = {
  malicious: "#8f1d14",
  harmless: "#3f7a34",
  unknown: "#6b6458",
} as const;
