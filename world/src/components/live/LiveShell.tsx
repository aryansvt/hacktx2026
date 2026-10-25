"use client";
import dynamic from "next/dynamic";
import { useEffect, useRef, useState, useCallback } from "react";
import { ArrowLeft, X, Bot, Flame, Ghost, Sparkles, User } from "lucide-react";
import { useDomain } from "@/lib/store";
import { useView, type Subview } from "@/lib/view-store";
import { appearance, eventText, location } from "@/lib/domain";
import { createMockAdapter } from "@/lib/mock";
import { backoff, createLiveAdapter, fetchStats, useConn } from "@/lib/live";
import { useDataMode, type DataMode } from "@/lib/data-mode";
import { useGuestFollow, useHashMode, useKioskTour } from "@/lib/modes";
import type { DataAdapter, SessionResponse } from "@/lib/contracts";
import styles from "./live.module.css";
import Timeline from "./Timeline";
import TopBar from "@/components/chrome/TopBar";
import Chronicle from "@/components/chrome/Chronicle";
import Heralds from "@/components/chrome/Heralds";
import Footer from "@/components/chrome/Footer";
const World = dynamic(() => import("./World"), {
  ssr: false,
  loading: () => null,
});
function elapsed(a: string, b: string) {
  const s = Math.max(0, Math.round((Date.parse(b) - Date.parse(a)) / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}
function Inspection({ adapter }: { adapter: DataAdapter | null }) {
  const view = useView(),
    data = useDomain((s) => s.data);
  const [response, setResponse] = useState<SessionResponse | null>(null),
    [error, setError] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    if (!adapter || !view.selectedSession) return;
    adapter
      .session(view.selectedSession)
      .then((r) => {
        if (active) {
          setResponse(r);
          setError("");
        }
      })
      .catch(() => {
        if (active) setError("Could not load this visit. Try again.");
      });
    return () => {
      active = false;
    };
  }, [adapter, view.selectedSession, retry]);
  useEffect(() => {
    heading.current?.focus();
  }, [view.subview, response?.session.session_id]);
  const session =
    response?.session.session_id === view.selectedSession
      ? response.session
      : null;
  if (error)
    return (
      <div className={`${styles.panel} ${styles.popup}`}>
        <p>{error}</p>
        <button onClick={() => setRetry((n) => n + 1)}>Retry visit</button>
        <button onClick={view.close}>Back to Activity</button>
      </div>
    );
  if (!session)
    return (
      <div className={`${styles.panel} ${styles.popup}`} role="status">
        Loading visit evidence…
      </div>
    );
  const aggregate = data.attackers[view.selectedAttacker ?? ""];
  const app = appearance(
    aggregate?.attacker ?? session.attacker,
    aggregate?.max_threat,
  );
  const events = response!.events;
  const evidence = events.flatMap((e) =>
    e.type === "classified" || e.type === "tripwire" ? e.detail.reasons : [],
  );
  const reasons = [...new Set(evidence)];
  const dossier = events.findLast((e) => e.type === "dossier");
  const name = `${app.name} from ${session.geo.city ?? "an unknown city"}`;
  const duration = session.ended_at
    ? elapsed(session.started_at, session.ended_at)
    : "Ongoing";
  const Icon =
    app.variant === "dragon"
      ? Flame
      : session.attacker.kind === "unknown"
        ? Ghost
        : session.attacker.kind === "bot"
          ? Bot
          : session.attacker.kind === "human"
            ? User
            : Sparkles;
  const back = () => {
    view.back();
    requestAnimationFrame(() =>
      document.getElementById(`action-${view.subview}`)?.focus(),
    );
  };
  return (
    <section
      className={`${styles.panel} ${styles.popup}`}
      aria-label="Creature inspection"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          if (view.subview !== "overview") back();
          else view.close();
        }
      }}
    >
      <button
        className={`${styles.icon} ${styles.panelClose}`}
        aria-label={
          view.subview !== "overview"
            ? "Back to creature overview"
            : view.origin === "activity"
              ? "Back to Event List"
              : "Close inspection"
        }
        onClick={view.subview !== "overview" ? back : view.close}
      >
        {view.subview !== "overview" || view.origin === "activity" ? (
          <ArrowLeft />
        ) : (
          <X />
        )}
      </button>
      <div className={styles.popupContent}>
        <h2 ref={heading} tabIndex={-1}>
          {view.subview === "overview"
            ? name
            : view.subview[0].toUpperCase() + view.subview.slice(1)}
        </h2>
        {view.subview === "overview" ? (
          <>
            <div className={styles.preview}>
              <Icon style={{ color: app.color }} />
              Creature preview · {app.name.toLowerCase()}
            </div>
            <p className={styles.facts}>
              <strong>
                Kind {session.attacker.kind} · Variant {app.variant} · Threat{" "}
                {session.attacker.threat === "med"
                  ? "medium"
                  : session.attacker.threat}
              </strong>
            </p>
            <p>
              Reputation {session.attacker.reputation} · Family{" "}
              {session.attacker.family ?? "not known"}
            </p>
            <p>
              <strong>
                Confidence {Math.round(session.attacker.confidence * 100)}% ·
                Why this classification?
              </strong>
            </p>
            <div className={styles.chips}>
              {reasons.length ? (
                reasons.map((r) => <span key={r}>{r}</span>)
              ) : (
                <span>Awaiting classification evidence</span>
              )}
            </div>
            <p>
              {location(session.geo)}
              <br />
              Client: {session.attacker.client ?? "not reported"}
              <br />
              Time spent: {duration} · Commands: {session.command_count}
            </p>
            <div className={styles.actions}>
              {(["replay", "details", "dossier"] as Subview[]).map((v) => (
                <button id={`action-${v}`} key={v} onClick={() => view.view(v)}>
                  {v[0].toUpperCase() + v.slice(1)}
                </button>
              ))}
            </div>
            {aggregate && aggregate.session_ids.length > 1 && (
              <label className={styles.sessionSelect}>
                Visit{" "}
                <select
                  aria-label="Selected visit"
                  value={session.session_id}
                  onChange={(e) =>
                    useView.setState({ selectedSession: e.target.value })
                  }
                >
                  {aggregate.session_ids.map((id, i) => (
                    <option key={id} value={id}>
                      {i + 1} · {data.sessions[id]?.status ?? "recorded"}
                    </option>
                  ))}
                </select>
                <span>{aggregate.visits} visits</span>
              </label>
            )}
          </>
        ) : view.subview === "replay" ? (
          <>
            <p>{name}</p>
            {!events.some((e) => e.type === "command") && (
              <p>No commands were recorded for this visit.</p>
            )}
            <ol className={styles.replay}>
              {events.map((e) => (
                <li key={e.event_id}>
                  <time>{elapsed(session.started_at, e.timestamp)}</time>
                  {eventText(e)}
                  {e.type === "command" && (
                    <pre>
                      Fortress reply: {e.detail.output || "(empty reply)"}
                    </pre>
                  )}
                </li>
              ))}
            </ol>
            <p>
              This replay follows the selected visit. Replies are simulated.
            </p>
          </>
        ) : view.subview === "details" ? (
          <div className={styles.details}>
            <p>
              This {app.name.toLowerCase()} represents{" "}
              {session.attacker.kind === "unknown"
                ? "an unclassified visitor"
                : `a ${session.attacker.kind}`}{" "}
              with {Math.round(session.attacker.confidence * 100)}% confidence
              and a{" "}
              {session.attacker.threat === "med"
                ? "medium"
                : session.attacker.threat}{" "}
              session threat. Reputation is {session.attacker.reputation}. Its
              reported family is {session.attacker.family ?? "not known"}.
            </p>
            <p>
              {reasons.length
                ? `Classification evidence: ${reasons.join("; ")}.`
                : "No classification evidence has arrived. Unknown traffic remains a shadow."}
            </p>
            <p>
              The connection originated in {location(session.geo)}, using{" "}
              {session.attacker.client ?? "an unreported client"}. Duration:{" "}
              {duration}. Commands: {session.command_count}. Aggregate threat
              across visits: {aggregate?.max_threat ?? session.attacker.threat}.
            </p>
          </div>
        ) : (
          <>
            <p>{name}</p>
            <dl className={styles.dossier}>
              {Object.entries({
                Kind: session.attacker.kind,
                Reputation: session.attacker.reputation,
                Variant: app.variant,
                Threat: session.attacker.threat,
                Family: session.attacker.family ?? "Not known",
                Confidence: `${Math.round(session.attacker.confidence * 100)}%`,
                Location: location(session.geo),
                Client: session.attacker.client ?? "Not reported",
                Session: `${duration} · ${session.command_count} commands`,
                Evidence: reasons.join("; ") || "Not yet reported",
              }).map(([k, v]) => (
                <div key={k} style={{ display: "contents" }}>
                  <dt>{k}</dt>
                  <dd>{v}</dd>
                </div>
              ))}
            </dl>
            <p>
              {dossier?.type === "dossier"
                ? dossier.detail.summary
                : "No dossier enrichment has arrived for this visit."}
            </p>
            {dossier?.type === "dossier" &&
              dossier.detail.sources
                .filter((s) => /^https?:\/\//.test(s.url))
                .map((s) => (
                  <a key={s.url} href={s.url} target="_blank" rel="noreferrer">
                    {s.title}
                  </a>
                ))}
          </>
        )}
      </div>
    </section>
  );
}
export default function LiveShell() {
  const view = useView();
  const hashMode = useHashMode();
  const kiosk = hashMode === "kiosk";
  useKioskTour(kiosk);
  useGuestFollow(hashMode === "guest");
  const [adapter, setAdapter] = useState<DataAdapter | null>(null);
  const worldRef = useRef<HTMLDivElement>(null),
    lineRef = useRef<SVGPolylineElement>(null);
  const { mode, choose, toggle } = useDataMode();
  const conn = useConn((s) => s.conn);
  useEffect(() => {
    if (!mode) return;
    const current = mode === "mock" ? createMockAdapter() : createLiveAdapter();
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
          unsubscribe = current.subscribe(useDomain.getState().ingest);
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
  }, [mode]);
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
    <main
      className={styles.shell}
      onKeyDown={(e) => {
        if (e.key === "Escape" && view.surface !== "none") {
          if (view.surface === "creature" && view.subview !== "overview")
            view.back();
          else view.close();
        }
      }}
    >
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
          <span>
            {mode === "mock"
              ? "Mock data, not real traffic"
              : "Live data from the honeypot"}
          </span>
          <label>
            Data{" "}
            <select
              aria-label="Data mode"
              value={mode}
              onChange={(e) => choose(e.target.value as DataMode)}
            >
              <option value="live">Live</option>
              <option value="mock">Mock</option>
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
      {view.surface === "creature" && <Inspection adapter={adapter} />}
      {!kiosk && <Timeline />}
      <Footer />
    </main>
  );
}
