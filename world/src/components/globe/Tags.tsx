"use client";
import { useEffect, useMemo, useRef } from "react";
import { useDomain } from "@/lib/store";
import { screen } from "@/lib/screen";
import styles from "./globe.module.css";

// small dom labels pinned to creatures: guest names, simulated tags, visit counts
export function Tags({
  selected,
  hovered,
}: {
  selected: string | null;
  hovered: string | null;
}) {
  const attackers = useDomain((s) => s.data.attackers);
  const events = useDomain((s) => s.data.events);
  const names = useMemo(() => {
    const m = new Map<string, string>();
    for (const e of Object.values(events))
      if (e.type === "session_start" && e.detail.guest_name)
        m.set(e.session_id, e.detail.guest_name);
    return m;
  }, [events]);
  const tags = useMemo(
    () =>
      Object.entries(attackers).flatMap(([k, a]) => {
        const badge =
          a.visits > 1 && (k === selected || k === hovered || a.visits >= 5)
            ? `×${a.visits}`
            : null;
        const label =
          a.source === "guest"
            ? (names.get(a.latest_session_id) ?? "Guest")
            : a.source === "team"
              ? "simulated"
              : null;
        if (!badge && !label) return [];
        return [{ k, label, badge, guest: a.source === "guest" }];
      }),
    [attackers, names, selected, hovered],
  );
  const refs = useRef(new Map<string, HTMLDivElement>());
  useEffect(() => {
    let raf = 0;
    const tick = () => {
      for (const [k, el] of refs.current) {
        const p = screen.creatures.get(k);
        if (!p || !p.visible) {
          el.style.opacity = "0";
          continue;
        }
        el.style.opacity = "1";
        el.style.transform = `translate(${p.x}px, ${p.y}px) translate(-50%, -100%)`;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return (
    <div className={styles.tags} aria-hidden="true">
      {tags.map((t) => (
        <div
          key={t.k}
          className={styles.tag}
          ref={(el) => {
            if (el) refs.current.set(t.k, el);
            else refs.current.delete(t.k);
          }}
        >
          {t.label && (
            <span className={t.guest ? styles.guest : styles.sim}>
              {t.label}
            </span>
          )}
          {t.badge && <span className={styles.badge}>{t.badge}</span>}
        </div>
      ))}
    </div>
  );
}
