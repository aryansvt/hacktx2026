"use client";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useView } from "@/lib/view-store";
import orn from "@/styles/ornament.module.css";
import styles from "./replay.module.css";

// replay mode only: says plainly that this is a recording
export default function ReplayBanner() {
  const reduce = useReducedMotion();
  // the creature page and the chronicle feed use this corner
  const free = useView((s) => s.surface === "none");
  return (
    <AnimatePresence>
      {free && (
        <motion.aside
          key="replay-banner"
          className={`${orn.panel} ${styles.banner}`}
          aria-label="Replay notice"
          // moves with the chronicle card under it
          initial={reduce ? { opacity: 0 } : { opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          exit={reduce ? { opacity: 0 } : { opacity: 0, y: 12 }}
          transition={{ duration: 0.28, ease: [0.23, 1, 0.32, 1] }}
        >
          <p>
            <span>Replaying real attacks recorded during HackTX 2026.</span>{" "}
            <span className={styles.offline}>The live trap is offline.</span>
          </p>
        </motion.aside>
      )}
    </AnimatePresence>
  );
}
