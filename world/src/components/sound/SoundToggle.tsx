"use client";
import { useEffect, useRef, useState } from "react";
import { Volume2, VolumeX } from "lucide-react";
import { bus } from "@/lib/bus";
import { chimeFor } from "./chime";
import styles from "./sound.module.css";

function bell(ctx: AudioContext, freq: number, at: number) {
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = "sine";
  osc.frequency.value = freq;
  gain.gain.setValueAtTime(0.0001, at);
  gain.gain.exponentialRampToValueAtTime(0.08, at + 0.01);
  gain.gain.exponentialRampToValueAtTime(0.0001, at + 1.2);
  osc.connect(gain).connect(ctx.destination);
  osc.start(at);
  osc.stop(at + 1.3);
}

export default function SoundToggle() {
  const [on, setOn] = useState(false);
  const ctx = useRef<AudioContext | null>(null);
  useEffect(() => {
    if (!on) return;
    return bus.on((e) => {
      const notes = chimeFor(e);
      const c = ctx.current;
      if (!notes || !c) return;
      notes.forEach((f, i) => bell(c, f, c.currentTime + i * 0.12));
    });
  }, [on]);
  return (
    <button
      className={styles.toggle}
      aria-pressed={on}
      aria-label={on ? "Turn sound off" : "Turn sound on"}
      title={on ? "Sound on: soft chimes for notable events" : "Sound off"}
      onClick={() => {
        // audio needs a click before it can start
        if (!ctx.current) ctx.current = new AudioContext();
        void ctx.current.resume();
        setOn((v) => !v);
      }}
    >
      {on ? <Volume2 size={19} /> : <VolumeX size={19} />}
    </button>
  );
}
