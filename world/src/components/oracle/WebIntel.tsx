"use client";
import { useMemo, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { ChevronDown, Eye } from "lucide-react";
import { useDomain } from "@/lib/store";
import { useOracle } from "./oracle-store";
import styles from "./oracle.module.css";

const fmt = new Intl.NumberFormat("en-US");

export default function WebIntel() {
  const events = useDomain((s) => s.data.events);
  const attackers = useDomain((s) => s.data.attackers);
  const knownBad = useDomain((s) => s.data.stats.by_reputation.malicious);
  const consulting = useOracle((s) => !!s.current);
  const [open, setOpen] = useState(true);
  const reduce = useReducedMotion();

  const { lookups, sources } = useMemo(() => {
    let lookups = 0,
      sources = 0;
    for (const e of Object.values(events))
      if (e.type === "dossier") {
        lookups++;
        sources += e.detail.sources.length;
      }
    return { lookups, sources };
  }, [events]);
  const unmasked = useMemo(
    () =>
      Object.values(attackers).filter(
        (a) => a.attacker.reputation === "malicious",
      ).length,
    [attackers],
  );

  const rows = [
    { n: lookups, label: lookups === 1 ? "lookup" : "lookups" },
    { n: sources, label: sources === 1 ? "source found" : "sources found" },
    {
      n: unmasked,
      label: unmasked === 1 ? "attacker unmasked" : "attackers unmasked",
      bad: true,
    },
    {
      n: knownBad,
      label: knownBad === 1 ? "known bad visitor" : "known bad visitors",
      bad: true,
    },
  ];

  return (
    <section className={styles.intel} aria-label="Web intel">
      <button
        type="button"
        className={styles.intelHead}
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <Eye className={styles.intelEye} size={22} aria-hidden />
        <span className={styles.intelTitles}>
          <span className={styles.intelTitle}>
            Web intel
            {consulting && (
              <span className={styles.consulting} role="status">
                consulting…
              </span>
            )}
          </span>
          <span className={styles.intelSub}>
            live web reputation lookup (SerpApi)
          </span>
        </span>
        <ChevronDown
          size={16}
          className={`${styles.chev} ${open ? styles.chevUp : ""}`}
          aria-hidden
        />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="grid"
            initial={reduce ? { opacity: 0 } : { height: 0, opacity: 0 }}
            animate={reduce ? { opacity: 1 } : { height: "auto", opacity: 1 }}
            exit={reduce ? { opacity: 0 } : { height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            style={{ overflow: "hidden" }}
          >
            <div className={styles.grid}>
              {rows.map((r) => (
                <div key={r.label} className={styles.stat}>
                  <div
                    className={`${styles.statNum} ${r.bad && r.n > 0 ? styles.statBad : ""}`}
                  >
                    {fmt.format(r.n)}
                  </div>
                  <div className={styles.statLabel}>{r.label}</div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
