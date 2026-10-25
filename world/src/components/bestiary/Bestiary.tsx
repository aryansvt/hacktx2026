"use client";
import { useEffect, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { BookOpen, X } from "lucide-react";
import { kindColor } from "@/lib/creatures";
import orn from "@/styles/ornament.module.css";
import styles from "./bestiary.module.css";

// the legend: how to read the creatures, in five seconds
const kinds = [
  { name: "Clay golem", kind: "bot", color: kindColor.bot, note: "a script knocking on every door" },
  { name: "Dark mage", kind: "human", color: kindColor.human, note: "a person typing by hand" },
  { name: "Fae", kind: "AI agent", color: kindColor.agent, note: "an AI acting on its own" },
  { name: "Shadow", kind: "unclassified", color: kindColor.unknown, note: "not sure yet" },
];
const marks = [
  { swatch: "aura", label: "Red aura", text: "Known bad on the web: stone golem, evil witch, cursed fae" },
  { swatch: "slime", label: "Slime", text: "Known harmless, like a research scanner" },
  { swatch: "dragon", label: "Dragon", text: "Reached critical threat. Circles the castle" },
  { swatch: "guest", label: "Gold ring", text: "A guest at our table in Austin" },
  { swatch: "visits", label: "×N", text: "How many times this visitor came back" },
  { swatch: "sim", label: "simulated", text: "Our own test traffic, not counted in stats" },
];

export default function Bestiary() {
  const [open, setOpen] = useState(false);
  const reduce = useReducedMotion();
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);
  return (
    <>
      <button
        className={styles.toggle}
        aria-expanded={open}
        aria-label={open ? "Close the bestiary" : "Open the bestiary, the creature key"}
        title="The Bestiary: how to read the creatures"
        onClick={() => setOpen((v) => !v)}
      >
        <BookOpen size={20} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.aside
            key="bestiary"
            className={`${orn.panel} ${styles.page}`}
            aria-label="The Bestiary"
            initial={reduce ? { opacity: 0 } : { opacity: 0, rotateY: 70 }}
            animate={reduce ? { opacity: 1 } : { opacity: 1, rotateY: 0 }}
            exit={reduce ? { opacity: 0 } : { opacity: 0, rotateY: 40 }}
            transition={{ duration: 0.35, ease: [0.23, 1, 0.32, 1] }}
          >
            <header className={orn.chapter}>
              <h2>The Bestiary</h2>
              <p>how to read the creatures</p>
            </header>
            <button className={styles.close} aria-label="Close the bestiary" onClick={() => setOpen(false)}>
              <X size={18} />
            </button>
            <p className={styles.lede}>
              Every visitor to our fake server becomes a creature. Color tells you what it is.
            </p>
            <ul className={styles.kinds}>
              {kinds.map((k) => (
                <li key={k.kind}>
                  <span className={styles.dot} style={{ background: k.color }} />
                  <span>
                    <strong>{k.name}</strong> <em>({k.kind})</em>
                    <small>{k.note}</small>
                  </span>
                </li>
              ))}
            </ul>
            <hr className={orn.goldRule} />
            <ul className={styles.marks}>
              {marks.map((m) => (
                <li key={m.label}>
                  <span className={`${styles.swatch} ${styles[m.swatch]}`}>
                    {m.swatch === "visits" ? "×3" : m.swatch === "sim" ? "sim" : ""}
                  </span>
                  <span>
                    <strong>{m.label}</strong> {m.text}
                  </span>
                </li>
              ))}
            </ul>
            <p className={styles.foot}>
              The castle in Dallas is our trap. Arcs show where each visitor came from.
            </p>
          </motion.aside>
        )}
      </AnimatePresence>
    </>
  );
}
