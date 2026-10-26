"use client";
import { useEffect, useRef, useState } from "react";
import { useDomain } from "@/lib/store";
import styles from "./live.module.css";
// attacks per bucket over 24h, stacked by kind
export default function Timeline({
  castleOpen,
  onCastle,
  badge = "LIVE",
}: {
  castleOpen: boolean;
  onCastle: () => void;
  badge?: string;
}) {
  const data = useDomain((s) => s.data);
  const chart = useRef<HTMLDivElement>(null);
  const [bucketCount, setBucketCount] = useState(64);
  useEffect(() => {
    if (!chart.current) return;
    const observer = new ResizeObserver(([entry]) =>
      setBucketCount(Math.max(8, Math.floor(entry.contentRect.width / 11.4))),
    );
    observer.observe(chart.current);
    return () => observer.disconnect();
  }, []);
  // live uses wild-only per_minute from /stats; mock uses fixture sessions
  const perMinute = data.stats.per_minute;
  const real = perMinute.length > 0;
  const recent = data.recent.map((id) => data.events[id]);
  const latest = real
    ? new Date().toISOString()
    : (recent[0]?.timestamp ?? "2026-10-25T12:00:00Z");
  const counts = Array.from({ length: bucketCount }, (_, i) => {
    const end =
      Date.parse(latest) -
      ((bucketCount - 1 - i) * 24 * 60 * 60 * 1000) / bucketCount;
    const start = end - (24 * 60 * 60 * 1000) / bucketCount;
    const inBucket = (t: string) =>
      Date.parse(t) > start && Date.parse(t) <= end;
    const time = new Date(end).toISOString().slice(11, 16);
    if (real) {
      const rows = perMinute.filter((m) => inBucket(m.t));
      const sum = (k: "bot" | "human" | "agent") =>
        rows.reduce((n, m) => n + m[k], 0);
      return {
        time,
        bot: sum("bot"),
        human: sum("human"),
        agent: sum("agent"),
      };
    }
    const rows = Object.values(data.sessions).filter(
      (e) => e.source === "mock" && inBucket(e.started_at),
    );
    return {
      time,
      bot: rows.filter((e) => e.attacker.kind === "bot").length,
      human: rows.filter((e) => e.attacker.kind === "human").length,
      agent: rows.filter((e) => e.attacker.kind === "agent").length,
    };
  });
  const peak = Math.max(1, ...counts.map((c) => c.bot + c.human + c.agent));
  return (
    <div
      className={styles.timeline}
      aria-label="Timeline, attacks over 24 hours"
    >
      <strong>Timeline</strong>
      <span className={styles.live}>{badge}</span>
      <div ref={chart} className={styles.chart}>
        <div className={styles.bars}>
          {counts.map((c, i) => (
            <div
              key={i}
              className={styles.bar}
              tabIndex={0}
              aria-label={`${c.time} UTC: ${c.bot + c.human + c.agent} visits`}
            >
              <span
                style={{
                  height:
                    (((28 * (c.bot + c.human + c.agent)) / peak) * c.agent) /
                    Math.max(1, c.bot + c.human + c.agent),
                  background: "#8257a6",
                }}
              />
              <span
                style={{
                  height:
                    (((28 * (c.bot + c.human + c.agent)) / peak) * c.human) /
                    Math.max(1, c.bot + c.human + c.agent),
                  background: "#287dd0",
                }}
              />
              <span
                style={{
                  height: Math.max(
                    1,
                    (((28 * (c.bot + c.human + c.agent)) / peak) * c.bot) /
                      Math.max(1, c.bot + c.human + c.agent),
                  ),
                  background: c.bot ? "#527845" : "var(--gold)",
                }}
              />
            </div>
          ))}
        </div>
        <div className={styles.ticks}>
          {Array.from({ length: 48 }, (_, i) => (
            <i key={i} />
          ))}
        </div>
        <span className={styles.now}>Now</span>
      </div>
      <button
        className={styles.castleButton}
        aria-expanded={castleOpen}
        title="Raw events, response times and classifier evidence"
        onClick={onCastle}
      >
        Beneath the Castle
      </button>
    </div>
  );
}
