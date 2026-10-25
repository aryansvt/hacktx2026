"use client";
import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { bus } from "@/lib/bus";
import { useDomain } from "@/lib/store";
import {
  enqueue,
  heraldCtx,
  heraldFor,
  remember,
  type Queued,
} from "./herald";
import styles from "./Heralds.module.css";

const SHOW_MS = 5000;

export default function Heralds() {
  const reduce = useReducedMotion();
  const [queue, setQueue] = useState<Queued[]>([]);
  const ctx = useRef(heraldCtx());
  const ready = useDomain((s) => s.ready);

  // countries already on the map when the snapshot lands are not news
  useEffect(() => {
    if (!ready) return;
    const { attackers, sessions } = useDomain.getState().data;
    for (const a of Object.values(attackers))
      if (a.source !== "guest") ctx.current.countries.add(a.geo.country);
    for (const s of Object.values(sessions))
      if (s.source !== "guest") ctx.current.countries.add(s.geo.country);
  }, [ready]);

  useEffect(
    () =>
      bus.on((e) => {
        const h = heraldFor(e, ctx.current);
        remember(e, ctx.current);
        if (h) setQueue((q) => enqueue(q, { ...h, id: e.event_id }));
      }),
    [],
  );

  const current = queue[0];
  useEffect(() => {
    if (!current) return;
    const t = setTimeout(
      () => setQueue((q) => (q[0]?.id === current.id ? q.slice(1) : q)),
      SHOW_MS,
    );
    return () => clearTimeout(t);
  }, [current]);

  return (
    <div className={styles.stage} aria-live="polite" role="status">
      <AnimatePresence mode="wait">
        {current && (
          <motion.div
            key={current.id}
            className={styles.ribbon}
            data-tone={current.tone}
            initial={reduce ? { opacity: 0 } : { opacity: 0, scaleX: 0.08 }}
            animate={{ opacity: 1, scaleX: 1 }}
            exit={
              reduce
                ? { opacity: 0 }
                : { opacity: 0, scaleX: 0.08, transition: { duration: 0.22 } }
            }
            transition={{ duration: 0.4, ease: [0.22, 1.1, 0.36, 1] }}
            onClick={() => setQueue((q) => q.slice(1))}
          >
            <motion.span
              className={styles.text}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: reduce ? 0 : 0.18, duration: 0.25 }}
            >
              <span className={styles.fantasy}>{current.fantasy}</span>
              <span className={styles.plain}>{current.plain}</span>
            </motion.span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
