"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { Pause, Play, RotateCcw } from "lucide-react";
import type { AttackEvent } from "@/lib/contracts";
import { lineOf, replayEvents, replayGaps, type Line } from "./replay";
import styles from "./creature.module.css";

const speeds = [1, 2, 4] as const;

export default function Replay({ events }: { events: AttackEvent[] }) {
  const steps = useMemo(() => replayEvents(events), [events]);
  const lines = useMemo(
    () => steps.map(lineOf).filter((l): l is Line => !!l),
    [steps],
  );
  const gaps = useMemo(() => replayGaps(steps), [steps]);
  const [shown, setShown] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState<(typeof speeds)[number]>(1);
  const screenRef = useRef<HTMLDivElement>(null);
  const hasCommands = steps.some((e) => e.type === "command");

  // advance one line at a time with the real (capped) gap
  useEffect(() => {
    if (!playing || shown >= lines.length) return;
    const t = setTimeout(
      () => setShown((n) => n + 1),
      shown === 0 ? 300 : gaps[shown] / speed,
    );
    return () => clearTimeout(t);
  }, [playing, shown, lines.length, gaps, speed]);

  useEffect(() => {
    const el = screenRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [shown]);

  const done = shown >= lines.length;
  const restart = () => {
    setShown(0);
    setPlaying(true);
  };

  return (
    <div className={styles.replayWrap}>
      {!hasCommands && (
        <p className={styles.empty}>
          This visitor never got past the gate. No commands to replay.
        </p>
      )}
      {lines.length > 0 && (
        <>
          <div className={styles.controls}>
            <button
              type="button"
              onClick={() => (done ? restart() : setPlaying((p) => !p))}
              aria-label={playing && !done ? "Pause replay" : "Play replay"}
            >
              {playing && !done ? <Pause size={15} /> : <Play size={15} />}
            </button>
            <button type="button" onClick={restart} aria-label="Restart replay">
              <RotateCcw size={15} />
            </button>
            <div className={styles.speeds} role="group" aria-label="Speed">
              {speeds.map((s) => (
                <button
                  key={s}
                  type="button"
                  aria-pressed={speed === s}
                  onClick={() => setSpeed(s)}
                >
                  {s}x
                </button>
              ))}
            </div>
            <span className={styles.progress}>
              {Math.min(shown, lines.length)}/{lines.length}
            </span>
          </div>
          <div
            className={styles.terminal}
            ref={screenRef}
            role="log"
            aria-live="polite"
            aria-label="Session replay"
          >
            {lines.slice(0, shown).map((l) => (
              <div key={l.id} className={`${styles.tl} ${styles[l.tone]}`}>
                {l.tone === "cmd" ? (
                  <>
                    <div className={styles.cmdRow}>
                      <span className={styles.prompt}>$</span>
                      <span className={styles.cmdText}>{l.text}</span>
                      {l.tag && <span className={styles.tag}>{l.tag}</span>}
                    </div>
                    {l.output && <pre className={styles.out}>{l.output}</pre>}
                  </>
                ) : (
                  <>
                    <span>{l.text}</span>
                    {l.output && <pre className={styles.out}>{l.output}</pre>}
                  </>
                )}
              </div>
            ))}
            {!done && <span className={styles.cursor} aria-hidden />}
          </div>
          <p className={styles.note}>
            Replayed with real timing (long pauses shortened). Replies came from
            our fake shell, nothing was executed.
          </p>
        </>
      )}
    </div>
  );
}
