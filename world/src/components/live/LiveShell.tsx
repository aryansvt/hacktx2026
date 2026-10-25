"use client";
import dynamic from "next/dynamic";
import { useEffect, useRef, useState, useCallback } from "react";
import { motion, useReducedMotion } from "framer-motion";
import {
  ArrowLeft,
  BookOpen,
  Maximize,
  X,
  Filter,
  Bot,
  Flame,
  Ghost,
  Sparkles,
  User,
} from "lucide-react";
import { useDomain } from "@/lib/store";
import { useView, type Subview } from "@/lib/view-store";
import { appearance, eventText, location } from "@/lib/domain";
import { createMockAdapter, mockRequested } from "@/lib/mock";
import type {
  DataAdapter,
  SessionResponse,
  AttackEvent,
} from "@/lib/contracts";
import styles from "./live.module.css";
const World = dynamic(() => import("./World"), {
  ssr: false,
  loading: () => null,
});
const disclosure =
  "This is a research honeypot built for HackTX 2026. Connection data is anonymized and deleted after the event.";
function elapsed(a: string, b: string) {
  const s = Math.max(0, Math.round((Date.parse(b) - Date.parse(a)) / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}
function age(e: AttackEvent, latest: string) {
  const seconds = Math.max(
    0,
    Math.round((Date.parse(latest) - Date.parse(e.timestamp)) / 1000),
  );
  return seconds < 2
    ? "Now"
    : seconds < 60
      ? `${seconds}s ago`
      : `${Math.floor(seconds / 60)}m ago`;
}
function Timeline() {
  const data = useDomain((s) => s.data);
  const chart = useRef<HTMLDivElement>(null);
  const [bucketCount, setBucketCount] = useState(64);
  useEffect(() => {
    if (!chart.current) return;
    const observer = new ResizeObserver(([entry]) =>
      setBucketCount(Math.max(8, Math.floor(entry.contentRect.width / 11.4))),
    );
    observer.observe(chart.current);
    return () => observer.disconnect();
  }, []);
  // mock history is explicitly separate from wild-only backend stats.
  const recent = data.recent.map((id) => data.events[id]);
  const latest = recent[0]?.timestamp ?? "2026-10-25T12:00:00Z";
  const counts = Array.from({ length: bucketCount }, (_, i) => {
    const end =
      Date.parse(latest) -
      ((bucketCount - 1 - i) * 24 * 60 * 60 * 1000) / bucketCount;
    const start = end - (24 * 60 * 60 * 1000) / bucketCount;
    const rows = Object.values(data.sessions).filter(
      (e) =>
        e.source === "mock" &&
        Date.parse(e.started_at) > start &&
        Date.parse(e.started_at) <= end,
    );
    return {
      time: new Date(end).toISOString().slice(11, 16),
      bot: rows.filter((e) => e.attacker.kind === "bot").length,
      human: rows.filter((e) => e.attacker.kind === "human").length,
      agent: rows.filter((e) => e.attacker.kind === "agent").length,
    };
  });
  return (
    <div
      className={styles.timeline}
      aria-label="Timeline, mock history over 24 hours"
    >
      <strong>Timeline</strong>
      <span className={styles.live}>LIVE</span>
      <div ref={chart} className={styles.chart}>
        <div className={styles.bars}>
          {counts.map((c, i) => (
            <div
              key={i}
              className={styles.bar}
              tabIndex={0}
              aria-label={`${c.time} UTC: ${c.bot + c.human + c.agent} mock visits`}
            >
              <span
                style={{
                  height:
                    (Math.min(28, c.bot * 3 + c.human * 3 + c.agent * 3) *
                      c.agent) /
                    Math.max(1, c.bot + c.human + c.agent),
                  background: "#8257a6",
                }}
              />
              <span
                style={{
                  height:
                    (Math.min(28, c.bot * 3 + c.human * 3 + c.agent * 3) *
                      c.human) /
                    Math.max(1, c.bot + c.human + c.agent),
                  background: "#287dd0",
                }}
              />
              <span
                style={{
                  height: Math.max(
                    1,
                    (Math.min(28, c.bot * 3 + c.human * 3 + c.agent * 3) *
                      c.bot) /
                      Math.max(1, c.bot + c.human + c.agent),
                  ),
                  background: c.bot ? "#527845" : "var(--gold)",
                }}
              />
            </div>
          ))}
        </div>
        <div className={styles.ticks}>
          {Array.from({ length: 48 }, (_, i) => (
            <i key={i} />
          ))}
        </div>
        <span className={styles.now}>Now</span>
      </div>
      <button disabled title="Available in milestone 2">
        View Event Log
      </button>
    </div>
  );
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
  const data = useDomain((s) => s.data),
    ready = useDomain((s) => s.ready),
    view = useView(),
    reduced = useReducedMotion();
  const [adapter, setAdapter] = useState<DataAdapter | null>(null);
  const worldRef = useRef<HTMLDivElement>(null),
    lineRef = useRef<SVGPolylineElement>(null),
    feedRef = useRef<HTMLDivElement>(null);
  const priorSurface = useRef(view.surface);
  const enabled = mockRequested(process.env.NEXT_PUBLIC_MOCK);
  useEffect(() => {
    if (!enabled) return;
    const current = createMockAdapter();
    let active = true;
    let unsubscribe = () => {};
    current.snapshot().then((s) => {
      if (active) {
        useDomain.getState().hydrate(s);
        setAdapter(current);
        unsubscribe = current.subscribe(useDomain.getState().ingest);
      }
    });
    return () => {
      active = false;
      unsubscribe();
      current.close();
      useDomain.getState().reset();
    };
  }, [enabled]);
  useEffect(() => {
    if (view.surface === "activity") {
      if (feedRef.current)
        feedRef.current.scrollTop = useView.getState().feedScroll;
      if (priorSurface.current === "creature")
        document.getElementById(view.focusId ?? "feed-heading")?.focus();
      else document.getElementById("feed-heading")?.focus();
    } else if (view.surface === "none" && priorSurface.current !== "none")
      document.getElementById("latest-activity")?.focus();
    priorSurface.current = view.surface;
  }, [view.surface, view.focusId]);
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
  const events = data.recent.map((id) => data.events[id]);
  const latest = events[0];
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
        className={`${styles.world} ${shifted ? (view.surface === "creature" && view.origin === "map" ? styles.direct : styles.shifted) : ""}`}
        aria-label="Interactive attacker globe"
      >
        <World onProjection={project} />
      </div>
      {view.surface === "creature" && (
        <svg className={styles.anchor} aria-hidden="true">
          <polyline
            ref={lineRef}
            fill="none"
            stroke="var(--blue)"
            strokeWidth="1"
            strokeDasharray="3 4"
          />
        </svg>
      )}
      <header className={styles.topbar}>
        <a
          href="/live"
          className={styles.brand}
          aria-label="Breadcrumbs, every attacker leaves a trail"
        >
          Breadcrumbs
        </a>
        <div
          className={styles.stats}
          aria-label="Wild traffic totals, mock visits excluded"
        >
          <span>
            <strong>Attacks</strong>
            {data.stats.total_sessions}
          </span>
          <span>
            <strong>Active</strong>
            {data.stats.active_now}
          </span>
          <span>
            <strong>Countries</strong>
            {data.stats.countries}
          </span>
          <span title="Simulated successful entries to the honeypot">
            <strong>Breaches</strong>
            {data.stats.breaches}
          </span>
        </div>
        <div className={styles.tools}>
          <button
            className={styles.icon}
            disabled
            aria-label="Hide Controls, available in milestone 2"
            title="Hide Controls: available in milestone 2"
          >
            <Maximize />
          </button>
          <button
            className={styles.icon}
            disabled
            aria-label="Creature Key, available in milestone 2"
            title="Creature Key: available in milestone 2"
          >
            <BookOpen />
          </button>
        </div>
      </header>
      <div className={styles.mode}>
        <span>
          {enabled
            ? "Mock visits excluded from wild totals"
            : "Live unavailable until M5"}
        </span>
        <label>
          Data{" "}
          <select
            aria-label="Data mode"
            value={enabled ? "mock" : "live"}
            disabled={!enabled}
            onChange={() => {}}
          >
            <option value="mock">Mock</option>
            <option value="live" disabled>
              Live (M5)
            </option>
          </select>
        </label>
      </div>
      <p className={`${styles.hint} ${shifted ? styles.shiftHint : ""}`}>
        {view.surface === "creature"
          ? "Selected creature stays visible"
          : view.surface === "activity"
            ? "Select an event to inspect its creature"
            : "Drag to explore · click a creature to inspect"}
      </p>
      {view.surface === "none" && (
        <button
          id="latest-activity"
          className={styles.latest}
          onClick={view.openActivity}
        >
          <strong>
            {latest
              ? `Latest: ${appearance(latest.attacker).name} ${eventText(latest).toLowerCase()}`
              : "Latest activity"}
          </strong>
          <span>
            {latest
              ? `${latest.geo.city ?? "Unknown city"} · ${age(latest, latest.timestamp)} · mock`
              : enabled
                ? "Loading mock encounters…"
                : "Live connection is not implemented yet."}
          </span>
          <span>Click to view all activity</span>
        </button>
      )}
      {view.surface === "activity" && (
        <motion.section
          className={`${styles.panel} ${styles.feed}`}
          initial={{ opacity: reduced ? 1 : 0.8 }}
          animate={{ opacity: 1 }}
          transition={{ duration: reduced ? 0 : 0.16 }}
          aria-label="Activity"
        >
          <h2 id="feed-heading" tabIndex={-1}>
            Live Feed
          </h2>
          <p className={styles.subtitle}>
            Newest first · select to fly there · mock
          </p>
          <button
            className={`${styles.icon} ${styles.filterButton}`}
            disabled
            aria-label="Filter Activity, available in milestone 2"
            title="Filters: available in milestone 2"
          >
            <Filter />
          </button>
          <button
            className={`${styles.icon} ${styles.panelClose}`}
            aria-label="Close Activity"
            onClick={view.close}
          >
            <X />
          </button>
          <div
            ref={feedRef}
            className={styles.feedList}
            onScroll={(e) =>
              useView.setState({ feedScroll: e.currentTarget.scrollTop })
            }
          >
            {events.map((e) => (
              <button
                id={`event-${e.event_id}`}
                key={e.event_id}
                className={styles.row}
                onClick={() => {
                  if (e.attacker.ip_hash)
                    view.select(
                      e.attacker.ip_hash,
                      e.session_id,
                      "activity",
                      `event-${e.event_id}`,
                    );
                }}
                disabled={!e.attacker.ip_hash}
              >
                <span>
                  <span>
                    {appearance(e.attacker).name} ·{" "}
                    {e.geo.city ?? "Unknown city"}
                  </span>
                  <span>
                    {eventText(e)}
                    {e.attacker.family ? ` · ${e.attacker.family}` : ""}
                  </span>
                  <small>Simulated</small>
                </span>
                <time>{age(e, latest?.timestamp ?? e.timestamp)}</time>
              </button>
            ))}
            {!events.length && (
              <p className={styles.empty}>
                {ready ? "No encounters yet." : "Waiting for mock data."}
              </p>
            )}
          </div>
        </motion.section>
      )}
      {view.surface === "creature" && <Inspection adapter={adapter} />}
      <Timeline />
      <footer className={styles.disclosure}>{disclosure}</footer>
    </main>
  );
}
