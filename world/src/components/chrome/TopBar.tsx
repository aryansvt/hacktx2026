"use client";
import { useDomain } from "@/lib/store";
import orn from "@/styles/ornament.module.css";
import Odometer from "./Odometer";
import styles from "./TopBar.module.css";

const counters = [
  {
    key: "total_sessions",
    label: "Attacks",
    tip: "Connections to the fake server since we opened the gates",
  },
  {
    key: "active_now",
    label: "Active now",
    tip: "Visitors connected to the fake server right now",
  },
  {
    key: "countries",
    label: "Countries",
    tip: "Countries the connections came from",
  },
  {
    key: "breaches",
    label: "Breaches",
    tip: "Times an attacker logged in to the fake server",
  },
] as const;

export default function TopBar() {
  const stats = useDomain((s) => s.data.stats);
  return (
    <header className={`${orn.panel} ${styles.bar}`}>
      <div className={styles.brand}>
        <span className={styles.initial} aria-hidden>
          B
        </span>
        <span className={styles.words}>
          <span className={styles.wordmark}>Breadcrumbs</span>
          <span className={styles.tagline}>every attacker leaves a trail</span>
        </span>
      </div>
      <dl className={styles.counters}>
        {counters.map((c) => (
          <div key={c.key} className={styles.counter} tabIndex={0}>
            <dt>{c.label}</dt>
            <dd>
              <Odometer value={stats[c.key]} />
            </dd>
            <span className={styles.tip} role="tooltip">
              {c.tip}
            </span>
          </div>
        ))}
        <span className={styles.caption}>wild traffic only</span>
      </dl>
    </header>
  );
}
