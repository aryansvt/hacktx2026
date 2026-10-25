// mirrors contracts/*.schema.json; public wire field names remain unchanged.
export type Kind = "bot" | "human" | "agent" | "unknown";
export type Threat = "low" | "med" | "high" | "critical";
export type Source = "wild" | "guest" | "team" | "mock";
export interface Geo {
  lat: number;
  lon: number;
  country: string;
  city: string | null;
}
export interface AttackerProfile {
  kind: Kind;
  confidence: number;
  reputation: "harmless" | "unknown" | "malicious";
  family: string | null;
  threat: Threat;
}
export interface Attacker extends AttackerProfile {
  client: string | null;
  ip_hash: string | null;
}
export interface DetailMap {
  session_start: { guest_name?: string };
  login_fail: { username: string };
  login_success: { username: string };
  command: {
    command: string;
    output: string;
    response_ms: number;
    answered_by: "engine" | "llm" | "cache";
    techniques: string[];
  };
  tripwire: { tripwire_id: string; reasons: string[] };
  classified: { reasons: string[] };
  dossier: { summary: string; sources: { title: string; url: string }[] };
  story: { story: string };
  session_end: { duration_s: number; command_count: number };
}
export type AttackEvent = {
  [K in keyof DetailMap]: {
    event_id: string;
    session_id: string;
    type: K;
    timestamp: string;
    source: Source;
    protocol: "ssh" | "http";
    geo: Geo;
    attacker: Attacker;
    detail: DetailMap[K];
  };
}[keyof DetailMap];
export interface SessionSummary {
  session_id: string;
  started_at: string;
  ended_at: string | null;
  source: Source;
  geo: Geo;
  attacker: Attacker;
  status: "approaching" | "at_gate" | "inside" | "ended";
  login_fails: number;
  command_count: number;
  story: string | null;
}
export interface AttackerSummary {
  ip_hash: string;
  visits: number;
  first_seen: string;
  last_seen: string;
  latest_session_id: string;
  source: Source;
  geo: Geo;
  attacker: AttackerProfile;
  max_threat: Threat;
  session_ids: string[];
}
export interface Stats {
  total_sessions: number;
  active_now: number;
  countries: number;
  breaches: number;
  by_kind: Record<Kind, number>;
  by_reputation: Record<Attacker["reputation"], number>;
  per_minute: { t: string; bot: number; human: number; agent: number }[];
}
export interface SessionResponse {
  session: SessionSummary;
  events: AttackEvent[];
}
export interface Snapshot {
  sessions: SessionSummary[];
  attackers: AttackerSummary[];
  stats: Stats;
  events: AttackEvent[];
}
export interface DataAdapter {
  mode: "mock" | "live";
  snapshot(): Promise<Snapshot>;
  session(id: string): Promise<SessionResponse>;
  subscribe(onEvent: (event: AttackEvent) => void): () => void;
  close(): void;
}
