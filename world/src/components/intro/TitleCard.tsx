"use client";
import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import styles from "./title.module.css";

const KEY = "breadcrumbs:title-seen";

// storybook title card: once per browser session, skippable, never in kiosk
export default function TitleCard({ disabled }: { disabled: boolean }) {
  const reduce = useReducedMotion();
  const [phase, setPhase] = useState<"hidden" | "page" | "opening">("hidden");
  useEffect(() => {
    // hash mode is read after mount, so check kiosk directly too
    if (disabled || window.location.hash === "#kiosk") return;
    let seen = false;
    try {
      seen = sessionStorage.getItem(KEY) === "1";
    } catch {}
    if (seen) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setPhase("page");
    const t = setTimeout(() => setPhase("opening"), 2800);
    return () => clearTimeout(t);
  }, [disabled]);
  const skip = useCallback(() => setPhase("opening"), []);
  useEffect(() => {
    if (phase !== "page") return;
    const onKey = () => skip();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [phase, skip]);
  useEffect(() => {
    if (phase !== "opening") return;
    // mark seen only once it has played, so a remount doesn't eat it
    try {
      sessionStorage.setItem(KEY, "1");
    } catch {}
    const t = setTimeout(() => setPhase("hidden"), reduce ? 300 : 1100);
    return () => clearTimeout(t);
  }, [phase, reduce]);
  const open = phase === "opening";
  const ease = [0.65, 0, 0.35, 1] as const;
  return (
    <AnimatePresence>
      {phase !== "hidden" && (
        <motion.div
          key="title"
          className={styles.stage}
          onClick={skip}
          role="dialog"
          aria-label="Breadcrumbs title card. Click or press any key to begin."
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
        >
          <motion.div
            className={`${styles.cover} ${styles.left}`}
            animate={
              open
                ? reduce
                  ? { opacity: 0 }
                  : { rotateY: -105, opacity: 0.4 }
                : {}
            }
            transition={{ duration: reduce ? 0.3 : 1, ease }}
          />
          <motion.div
            className={`${styles.cover} ${styles.right}`}
            animate={
              open
                ? reduce
                  ? { opacity: 0 }
                  : { rotateY: 105, opacity: 0.4 }
                : {}
            }
            transition={{ duration: reduce ? 0.3 : 1, ease }}
          />
          <motion.div
            className={styles.text}
            initial={reduce ? { opacity: 0 } : { opacity: 0, y: 12 }}
            animate={open ? { opacity: 0 } : { opacity: 1, y: 0 }}
            transition={{
              duration: open ? 0.25 : 0.8,
              ease: [0.23, 1, 0.32, 1],
            }}
          >
            <span className={styles.initial} aria-hidden="true">
              O
            </span>
            <p className={styles.line}>
              nce upon a hack, a little tile shop left its door ajar…
            </p>
            <p className={styles.sub}>
              Every creature you&rsquo;re about to meet is a real visitor to our
              trap server.
            </p>
            <p className={styles.skip}>
              click or press any key to open the book
            </p>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
