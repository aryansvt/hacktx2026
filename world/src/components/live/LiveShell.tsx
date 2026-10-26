"use client";
import dynamic from "next/dynamic";
import { useEffect, useRef, useState, useCallback } from "react";
import { useDomain } from "@/lib/store";
import { useView } from "@/lib/view-store";
import { createMockAdapter } from "@/lib/mock";
import { createReplayAdapter } from "@/lib/replay";
import { backoff, createLiveAdapter, fetchStats, useConn } from "@/lib/live";
import { useDataMode, type DataMode } from "@/lib/data-mode";
import { useGuestFollow, useHashMode, useKioskTour } from "@/lib/modes";
import type { DataAdapter } from "@/lib/contracts";
import styles from "./live.module.css";
import Timeline from "./Timeline";
import TopBar from "@/components/chrome/TopBar";
import Chronicle from "@/components/chrome/Chronicle";
import Heralds from "@/components/chrome/Heralds";
import Footer from "@/components/chrome/Footer";
import CreaturePage from "@/components/creature/CreaturePage";
import Oracle from "@/components/oracle/Oracle";
import WebIntel from "@/components/oracle/WebIntel";
import Bestiary from "@/components/bestiary/Bestiary";
import Undercroft from "@/components/castle/Undercroft";
import TitleCard from "@/components/intro/TitleCard";
import SoundToggle from "@/components/sound/SoundToggle";
import DevDataToggle from "./DevDataToggle";
const World = dynamic(() => import("./World"), {
  ssr: false,
  loading: () => null,
});
const modeLabel: Record<DataMode, string> = {
  live: "Live data from the honeypot",
  replay: "Recorded attacks from HackTX 2026",
  mock: "Mock data, not real traffic",
};
const modeName: Record<DataMode, string> = {
  live: "Live",
  replay: "Replay",
  mock: "Mock",
};
export default function LiveShell() {
  const view = useView();
  const hashMode = useHashMode();
  const [castle, setCastle] = useState(false);
  const closeCastle = useCallback(() => setCastle(false), []);
  const kiosk = hashMode === "kiosk";
  useKioskTour(kiosk);
  useGuestFollow(hashMode === "guest");
  const [adapter, setAdapter] = useState<DataAdapter | null>(null);
  const worldRef = useRef<HTMLDivElement>(null),
    lineRef = useRef<SVGPolylineElement>(null);
  const { mode, data, choose, toggle, options } = useDataMode();
  const conn = useConn((s) => s.conn);
  useEffect(() => {
    if (!mode) return;
    const current =
      mode === "mock"
        ? createMockAdapter(data)
        : mode === "replay"
          ? createReplayAdapter()
          : createLiveAdapter();
    let active = true;
    let unsubscribe = () => {};
    let poll: ReturnType<typeof setInterval> | undefined;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const load = (tries = 0) =>
      current
        .snapshot()
        .then((s) => {
          if (!active) return;
          useDomain.getState().hydrate(s);
          setAdapter(current);
          const store = useDomain.getState();
          unsubscribe = current.subscribe(store.ingest, {
            stats: store.setStats,
            reset: store.hydrate,
          });
          if (current.mode === "live")
            poll = setInterval(() => {
              fetchStats()
                .then((st) => active && useDomain.getState().setStats(st))
                .catch(() => {});
            }, 10_000);
        })
        .catch(() => {
          if (active) retry = setTimeout(() => load(tries + 1), backoff(tries));
        });
    load();
    return () => {
      active = false;
      clearInterval(poll);
      clearTimeout(retry);
      unsubscribe();
      current.close();
      useDomain.getState().reset();
    };
  }, [mode, data]);
  const project = useCallback((x: number, y: number) => {
    const r = worldRef.current?.getBoundingClientRect();
    const popup = document
      .querySelector('[aria-label="Creature inspection"]')
      ?.getBoundingClientRect();
    if (r && popup && lineRef.current)
      lineRef.current.setAttribute(
        "points",
        `${popup.right},${popup.top + popup.height / 2} ${popup.right + 80},${popup.top + popup.height / 2} ${r.left + x},${r.top + y}`,
      );
  }, []);
  const shifted = view.surface !== "none";
  return (
    <main className={styles.shell}>
      <div
        ref={worldRef}
        className={`${styles.world} ${shifted ? styles.shifted : ""}`}
        aria-label="Interactive attacker globe"
      >
        <World onProjection={project} />
      </div>
      {view.surface === "creature" && (
        <svg className={styles.anchor} aria-hidden="true">
          <polyline
            ref={lineRef}
            fill="none"
            stroke="var(--gold)"
            strokeWidth="1.2"
            strokeDasharray="3 4"
          />
        </svg>
      )}
      {!kiosk && <TopBar />}
      <Heralds />
      {!kiosk && <Chronicle />}
      {mode === "live" && conn === "reconnecting" && (
        <p className={styles.pill} role="status">
          Reconnecting to the live feed…
        </p>
      )}
      {toggle && mode && !kiosk && (
        <div className={styles.mode}>
          <span>{modeLabel[mode]}</span>
          <label>
            Data{" "}
            <select
              aria-label="Data mode"
              value={mode}
              onChange={(e) => choose(e.target.value as DataMode)}
            >
              {options.map((m) => (
                <option key={m} value={m}>
                  {modeName[m]}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}
      <p
        className={`${styles.hint} ${shifted ? styles.shiftHint : ""}`}
        hidden={kiosk}
      >
        {view.surface === "creature"
          ? "Drag to look around · Esc to close"
          : view.surface === "activity"
            ? "Pick an event to meet its creature"
            : "Drag to explore · click a creature to inspect"}
      </p>
      <CreaturePage adapter={adapter} />
      {!kiosk && <WebIntel />}
      {!kiosk && <Bestiary />}
      {!kiosk && <SoundToggle />}
      <Oracle />
      <TitleCard disabled={kiosk} />
      {process.env.NODE_ENV !== "production" && (
        <DevDataToggle current={data} />
      )}
      {!kiosk && (
        <Timeline castleOpen={castle} onCastle={() => setCastle((v) => !v)} />
      )}
      {!kiosk && <Undercroft open={castle} onClose={closeCastle} />}
      <Footer />
    </main>
  );
}
