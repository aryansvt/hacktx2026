"use client";
import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { X } from "lucide-react";
import { useDomain } from "@/lib/store";
import orn from "@/styles/ornament.module.css";
import { answerSplit, latestReasons, perSecond, redacted } from "./stats";
import styles from "./undercroft.module.css";

// "beneath the castle": the raw machinery, to prove it's real
export default function Undercroft({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const reduce = useReducedMotion();
  const recent = useDomain((s) => s.data.recent);
  const byId = useDomain((s) => s.data.events);
  const events = useMemo(
    () => recent.map((id) => byId[id]).filter(Boolean),
    [recent, byId],
  );
  const [now, setNow] = useState(0);
  useEffect(() => {
    if (!open) return;
    const tick = () => setNow(Date.now());
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  const split = answerSplit(events);
  const reasons = latestReasons(events);
  const eps = now ? perSecond(events, now) : 0;
  return (
    <AnimatePresence>
      {open && (
        <motion.section
          key="undercroft"
          className={`${orn.panel} ${styles.drawer}`}
          aria-label="Beneath the Castle"
          initial={reduce ? { opacity: 0 } : { opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          exit={reduce ? { opacity: 0 } : { opacity: 0, y: 30 }}
          transition={{ duration: 0.3, ease: [0.23, 1, 0.32, 1] }}
        >
          <header className={`${orn.chapter} ${styles.head}`}>
            <h2>Beneath the Castle</h2>
            <p>
              under the hood: raw events, response times and why we labeled each
              visitor
            </p>
          </header>
          <button
            className={styles.close}
            aria-label="Close Beneath the Castle"
            onClick={onClose}
          >
            <X size={18} />
          </button>
          <div className={styles.figures}>
            <Figure
              label="Events per second"
              value={eps.toFixed(1)}
              hint="last 30 seconds"
            />
            <Figure
              label="Rules engine"
              value={`${split.engine.avg} ms`}
              hint={`${split.engine.count} replies from our hand-written fake shell`}
            />
            <Figure
              label="LLM"
              value={`${split.llm.avg} ms`}
              hint={`${split.llm.count} replies the rules didn't cover, written by an AI`}
            />
            <Figure
              label="Cache"
              value={`${split.cache.avg} ms`}
              hint={`${split.cache.count} replies reused from an earlier LLM answer`}
            />
          </div>
          <hr className={orn.goldRule} />
          <div className={styles.cols}>
            <div>
              <h3>Why we labeled them</h3>
              {reasons.length ? (
                <ul className={styles.reasons}>
                  {reasons.map((r) => (
                    <li
                      key={r.reason}
                      className={r.type === "tripwire" ? styles.trip : ""}
                    >
                      {r.reason}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className={styles.empty}>
                  No classifier verdicts in this window yet.
                </p>
              )}
            </div>
            <div className={styles.rawCol}>
              <h3>Raw events, newest first</h3>
              <ol className={styles.raw}>
                {events.slice(0, 40).map((e) => (
                  <li key={e.event_id}>
                    <time>{e.timestamp.slice(11, 19)}</time> <b>{e.type}</b>{" "}
                    <code>{redacted(e)}</code>
                  </li>
                ))}
                {!events.length && (
                  <li className={styles.empty}>
                    Waiting for the next event from the trap…
                  </li>
                )}
              </ol>
            </div>
          </div>
        </motion.section>
      )}
    </AnimatePresence>
  );
}

function Figure({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className={styles.figure} title={hint}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{hint}</small>
    </div>
  );
}
