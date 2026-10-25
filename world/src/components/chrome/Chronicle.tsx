"use client";
import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { X, BookOpen } from "lucide-react";
import { useDomain } from "@/lib/store";
import { useView } from "@/lib/view-store";
import { creatureKey } from "@/lib/domain";
import { creatureOf, sourceTag } from "@/lib/creatures";
import type { AttackerSummary, Source } from "@/lib/contracts";
import orn from "@/styles/ornament.module.css";
import { sentence, sessionSentence, parts } from "./sentence";
import { ago, flagOf, placeOf, countryName } from "./place";
import styles from "./Chronicle.module.css";

interface Row {
  id: string;
  key: string;
  session: string;
  text: string;
  time: string;
  country: string;
  place: string;
  color: string;
  initial: string;
  source: Source;
}

function useNow(ms = 15000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

function useRows(limit: number): Row[] {
  const recent = useDomain((s) => s.data.recent);
  const events = useDomain((s) => s.data.events);
  const sessions = useDomain((s) => s.data.sessions);
  const attackers = useDomain((s) => s.data.attackers);
  return useMemo(() => {
    const look = (key: string): AttackerSummary | undefined => attackers[key];
    const fromEvents: Row[] = [];
    for (const id of recent) {
      const e = events[id];
      if (!e) continue;
      const key = creatureKey(e);
      const a = look(key);
      const c = a
        ? creatureOf(a.attacker, a.max_threat, a.visits)
        : creatureOf(e.attacker);
      fromEvents.push({
        id,
        key,
        session: e.session_id,
        text: sentence(e, a),
        time: e.timestamp,
        country: e.geo.country,
        place: placeOf(e.geo),
        color: c.color,
        initial: c.name[0],
        source: e.source,
      });
      if (fromEvents.length >= limit) break;
    }
    if (fromEvents.length) return fromEvents;
    // rest-only start: show the latest visits so the page is never blank
    return Object.values(sessions)
      .sort((x, y) => Date.parse(y.started_at) - Date.parse(x.started_at))
      .slice(0, limit)
      .map((s) => {
        const key = creatureKey(s);
        const a = look(key);
        const c = a
          ? creatureOf(a.attacker, a.max_threat, a.visits)
          : creatureOf(s.attacker);
        return {
          id: s.session_id,
          key,
          session: s.session_id,
          text: sessionSentence(s, a),
          time: s.ended_at ?? s.started_at,
          country: s.geo.country,
          place: placeOf(s.geo),
          color: c.color,
          initial: c.name[0],
          source: s.source,
        };
      });
  }, [recent, events, sessions, attackers, limit]);
}

function Sentence({ text }: { text: string }) {
  return (
    <>
      {parts(text).map((p, i) =>
        i % 2 ? (
          <code key={i} className={styles.code}>
            {p}
          </code>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}

function Emblem({ row }: { row: Row }) {
  return (
    <span
      className={`${orn.seal} ${styles.emblem}`}
      style={{ ["--seal" as string]: row.color }}
      aria-hidden
    >
      {row.initial}
    </span>
  );
}

function Meta({ row, now }: { row: Row; now: number }) {
  const flag = flagOf(row.country);
  const tag = sourceTag(row.source);
  const country = countryName(row.country);
  return (
    <span className={styles.meta}>
      {flag && (
        <span className={styles.flag} title={country ?? undefined}>
          {flag}
        </span>
      )}
      <span>{row.place}</span>
      <span aria-hidden>·</span>
      <time dateTime={row.time}>{ago(row.time, now)}</time>
      {tag && <span className={styles.tag}>{tag}</span>}
    </span>
  );
}

export default function Chronicle() {
  const surface = useView((s) => s.surface);
  const reduce = useReducedMotion();
  return (
    <>
      <AnimatePresence>
        {surface === "none" && <Card key="card" reduce={!!reduce} />}
      </AnimatePresence>
      <AnimatePresence>
        {surface === "activity" && <Feed key="feed" reduce={!!reduce} />}
      </AnimatePresence>
    </>
  );
}

function Card({ reduce }: { reduce: boolean }) {
  const [row] = useRows(1);
  const now = useNow();
  const open = useView((s) => s.openActivity);
  return (
    <motion.div
      role="button"
      tabIndex={0}
      className={`${orn.panel} ${styles.card}`}
      onClick={open}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      }}
      initial={reduce ? { opacity: 0 } : { opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      exit={reduce ? { opacity: 0 } : { opacity: 0, y: 12 }}
      transition={{ duration: 0.28, ease: [0.23, 1, 0.32, 1] }}
      aria-label="Open the chronicle"
    >
      <span className={styles.cardHead}>
        <span className={orn.ribbon}>The Chronicle</span>
        <span className={styles.sub}>latest activity</span>
      </span>
      {row ? (
        <span className={styles.cardBody}>
          <Emblem row={row} />
          <span className={styles.cardText}>
            <AnimatePresence mode="popLayout" initial={false}>
              <motion.span
                key={row.id}
                className={styles.latest}
                initial={reduce ? { opacity: 0 } : { opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={reduce ? { opacity: 0 } : { opacity: 0, y: -10 }}
                transition={{ duration: 0.25, ease: [0.23, 1, 0.32, 1] }}
              >
                <Sentence text={row.text} />
              </motion.span>
            </AnimatePresence>
            <Meta row={row} now={now} />
          </span>
        </span>
      ) : (
        <span className={styles.empty}>
          The gates are quiet. Waiting for the first visitor.
        </span>
      )}
      <span className={styles.more}>
        <BookOpen size={14} aria-hidden /> Open the chronicle
      </span>
    </motion.div>
  );
}

function Feed({ reduce }: { reduce: boolean }) {
  const rows = useRows(80);
  const now = useNow();
  const select = useView((s) => s.select);
  const close = useView((s) => s.close);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [close]);
  return (
    <motion.section
      className={`${orn.panel} ${styles.feed}`}
      aria-label="The Chronicle"
      style={{ transformOrigin: "left center", transformPerspective: 1400 }}
      initial={reduce ? { opacity: 0 } : { opacity: 0, rotateY: -80 }}
      animate={{ opacity: 1, rotateY: 0 }}
      exit={reduce ? { opacity: 0 } : { opacity: 0, rotateY: -70 }}
      transition={{ duration: 0.35, ease: [0.23, 1, 0.32, 1] }}
    >
      <header className={styles.feedHead}>
        <div className={orn.chapter}>
          <h2>The Chronicle</h2>
          <span>every event, newest first</span>
        </div>
        <button
          type="button"
          className={styles.close}
          onClick={close}
          aria-label="Close the chronicle"
        >
          <X size={18} aria-hidden />
        </button>
      </header>
      <hr className={orn.goldRule} />
      {rows.length === 0 ? (
        <p className={styles.empty}>
          Nothing written yet. The first visitor will show up here.
        </p>
      ) : (
        <ol className={styles.list}>
          <AnimatePresence initial={false}>
            {rows.map((row) => (
              <motion.li
                key={row.id}
                initial={reduce ? { opacity: 0 } : { opacity: 0, y: -12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, ease: [0.23, 1, 0.32, 1] }}
              >
                <button
                  type="button"
                  className={styles.row}
                  onClick={() => select(row.key, row.session, "activity", row.id)}
                >
                  <Emblem row={row} />
                  <span className={styles.rowText}>
                    <span className={styles.line}>
                      <Sentence text={row.text} />
                    </span>
                    <Meta row={row} now={now} />
                  </span>
                </button>
              </motion.li>
            ))}
          </AnimatePresence>
        </ol>
      )}
    </motion.section>
  );
}
