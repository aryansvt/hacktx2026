"use client";
import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import type { AttackEvent } from "@/lib/contracts";
import { bus } from "@/lib/bus";
import { screen } from "@/lib/screen";
import { creatureKey } from "@/lib/domain";
import { useDomain } from "@/lib/store";
import { creatureOf } from "@/lib/creatures";
import { domainOf, verdictColor, verdictLabel } from "../creature/replay";
import Seal from "../creature/Seal";
import { useOracle } from "./oracle-store";
import styles from "./oracle.module.css";

type Dossier = Extract<AttackEvent, { type: "dossier" }>;
type Phase = "seek" | "cards" | "seal" | "out";

// distance from the overlay's top edge to the ring center
const RING_TOP = 64;
const RING = 200;
const W = 460;
// ring center sits RING_TOP + RING / 2 from the top; cards and label below
const H = RING_TOP + RING + 170;
const runes = "ᚠᚢᚦᚨᚱᚲᚷᚹᚺᚾᛁᛃᛇᛈᛉᛊᛏᛒᛖᛗᛚᛜᛞᛟ ".repeat(2);

export default function Oracle() {
  const current = useOracle((s) => s.current);
  const next = useOracle((s) => s.next);

  useEffect(
    () =>
      bus.on((e) => {
        if (e.type === "dossier") useOracle.getState().push(e);
      }),
    [],
  );

  return (
    <AnimatePresence>
      {current && <Moment key={current.event_id} e={current} onDone={next} />}
    </AnimatePresence>
  );
}

function Moment({ e, onDone }: { e: Dossier; onDone: () => void }) {
  const reduce = useReducedMotion();
  const box = useRef<HTMLDivElement>(null);
  const [phase, setPhase] = useState<Phase>("seek");
  const key = creatureKey(e);
  const max = useDomain((s) => s.data.attackers[key]?.max_threat);
  const visits = useDomain((s) => s.data.attackers[key]?.visits);
  const creature = creatureOf(
    e.attacker,
    max ?? e.attacker.threat,
    visits,
    e.source,
  );
  const sources = e.detail.sources.slice(0, 4);
  const verdict = e.attacker.reputation;

  // timeline: ring, then cards one by one, then the seal, then fade
  useEffect(() => {
    const cardsAt = 1400;
    const sealAt = cardsAt + sources.length * 280 + 300;
    const outAt = sealAt + 1800;
    const ts = [
      setTimeout(() => setPhase("cards"), cardsAt),
      setTimeout(() => setPhase("seal"), sealAt),
      setTimeout(() => setPhase("out"), outAt),
      setTimeout(onDone, outAt + 450),
    ];
    return () => ts.forEach(clearTimeout);
  }, [sources.length, onDone]);

  // follow the creature on screen, or sit under the herald
  useEffect(() => {
    let raf = 0;
    const tick = () => {
      const el = box.current;
      if (el) {
        const vw = window.innerWidth,
          vh = window.innerHeight;
        const p = screen.creatures.get(key);
        let x = vw / 2,
          y = Math.max(240, vh * 0.28);
        if (p?.visible) {
          x = p.x;
          y = p.y;
        }
        const left = Math.min(Math.max(x - W / 2, 8), vw - W - 8);
        const top = Math.min(
          Math.max(y - RING_TOP - RING / 2, 110),
          vh - H - 90,
        );
        el.style.transform = `translate3d(${left}px, ${Math.max(8, top)}px, 0)`;
      }
      raf = requestAnimationFrame(tick);
    };
    tick();
    return () => cancelAnimationFrame(raf);
  }, [key]);

  const shown = phase !== "seek";
  const sealed = phase === "seal" || phase === "out";

  return (
    <div className={styles.anchor} ref={box}>
      <motion.div
        className={styles.moment}
        role="status"
        aria-live="polite"
        initial={{ opacity: 0 }}
        animate={{ opacity: phase === "out" ? 0 : 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: phase === "out" ? 0.45 : 0.3 }}
      >
        <div className={styles.text}>
          <p className={styles.consult}>
            {sealed ? "The oracle has spoken" : "Consulting the oracle…"}
          </p>
          <p className={styles.plain}>
            {sealed
              ? `${sources.length} web source${sources.length === 1 ? "" : "s"} found for this visitor`
              : "Searching the web for this visitor's reputation"}
          </p>
        </div>

        <motion.div
          className={styles.ring}
          initial={reduce ? { opacity: 0 } : { opacity: 0, scale: 0.3 }}
          animate={reduce ? { opacity: 1 } : { opacity: 1, scale: 1 }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        >
          <svg viewBox="0 0 200 200" className={styles.ringSvg}>
            <defs>
              <radialGradient id="oracle-glow">
                <stop offset="0%" stopColor="rgba(240,207,106,0.35)" />
                <stop offset="70%" stopColor="rgba(240,207,106,0.08)" />
                <stop offset="100%" stopColor="rgba(240,207,106,0)" />
              </radialGradient>
              <path
                id="oracle-rune-path"
                d="M100,100 m-78,0 a78,78 0 1,1 156,0 a78,78 0 1,1 -156,0"
              />
            </defs>
            <circle cx="100" cy="100" r="98" fill="url(#oracle-glow)" />
            <g className={reduce ? undefined : styles.spin}>
              <circle cx="100" cy="100" r="92" className={styles.stroke} />
              {Array.from({ length: 72 }, (_, i) => (
                <line
                  key={i}
                  x1="100"
                  y1={i % 6 === 0 ? 8 : 11}
                  x2="100"
                  y2="15"
                  transform={`rotate(${i * 5} 100 100)`}
                  className={styles.tick}
                />
              ))}
              <text className={styles.runes}>
                <textPath href="#oracle-rune-path">{runes}</textPath>
              </text>
            </g>
            <g className={reduce ? undefined : styles.spinBack}>
              <circle
                cx="100"
                cy="100"
                r="64"
                className={styles.stroke}
                strokeDasharray="3 6"
              />
              <path
                d="M100 40 L152 130 L48 130 Z M100 160 L48 70 L152 70 Z"
                className={styles.star}
              />
            </g>
          </svg>
          <AnimatePresence>
            {sealed && (
              <motion.div
                className={styles.seal}
                initial={
                  reduce
                    ? { opacity: 0 }
                    : { opacity: 0, scale: 1.6, rotate: -8 }
                }
                animate={
                  reduce
                    ? { opacity: 1 }
                    : { opacity: 1, scale: [1.6, 0.94, 1], rotate: -4 }
                }
                transition={
                  reduce
                    ? { duration: 0.3 }
                    : { duration: 0.42, times: [0, 0.7, 1], ease: "easeOut" }
                }
              >
                <Seal
                  color={verdictColor[verdict]}
                  label={verdictLabel[verdict]}
                  size={96}
                />
              </motion.div>
            )}
          </AnimatePresence>
          <AnimatePresence>
            {sealed && (
              <motion.span
                className={styles.ribbon}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: reduce ? 0 : 0.25, duration: 0.3 }}
              >
                {creature.label}
              </motion.span>
            )}
          </AnimatePresence>
        </motion.div>

        <div className={styles.cards}>
          {sources.map((s, i) => {
            const mid = (sources.length - 1) / 2;
            const off = i - mid;
            const rot = off * 7;
            const x = off * 104;
            const y = Math.abs(off) * 8;
            return (
              <motion.div
                key={s.url + i}
                className={styles.card}
                initial={
                  reduce
                    ? { opacity: 0, x, y, rotate: rot }
                    : { opacity: 0, x: 0, y: -90, rotate: 0, scale: 0.5 }
                }
                animate={
                  shown
                    ? reduce
                      ? { opacity: 1, x, y, rotate: rot }
                      : { opacity: 1, x, y, rotate: rot, scale: 1 }
                    : undefined
                }
                transition={{
                  delay: i * (reduce ? 0.1 : 0.28),
                  type: reduce ? "tween" : "spring",
                  stiffness: 260,
                  damping: 22,
                  duration: reduce ? 0.2 : undefined,
                }}
              >
                <span className={styles.cardPip} aria-hidden>
                  ✦
                </span>
                <span className={styles.cardTitle}>{s.title}</span>
                <span className={styles.cardDomain}>{domainOf(s.url)}</span>
              </motion.div>
            );
          })}
          {sources.length === 0 && shown && (
            <p className={styles.noCards}>No pages mention this visitor.</p>
          )}
        </div>

        <p className={styles.serp}>live web reputation lookup (SerpApi)</p>
      </motion.div>
    </div>
  );
}
