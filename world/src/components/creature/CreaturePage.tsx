"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { ExternalLink, RefreshCw, X } from "lucide-react";
import type {
  AttackEvent,
  DataAdapter,
  SessionResponse,
} from "@/lib/contracts";
import { useDomain } from "@/lib/store";
import { useView } from "@/lib/view-store";
import { creatureKey, eventOrder, location } from "@/lib/domain";
import { creatureOf, kindLabel, sourceTag, threatLabel } from "@/lib/creatures";
import Emblem from "./Emblem";
import Seal from "./Seal";
import Replay from "./ReplayTerminal";
import {
  domainOf,
  latestOf,
  reasonsOf,
  relativeTime,
  threatColor,
  verdictColor,
  verdictLabel,
} from "./replay";
import styles from "./creature.module.css";

type Tab = "replay" | "story" | "dossier";
const tabs: Tab[] = ["replay", "story", "dossier"];
const tabLabel: Record<Tab, string> = {
  replay: "Replay",
  story: "Story",
  dossier: "Dossier",
};

export default function CreaturePage({
  adapter,
}: {
  adapter: DataAdapter | null;
}) {
  const surface = useView((s) => s.surface);
  const key = useView((s) => s.selectedAttacker);
  const reduce = useReducedMotion();
  const open = surface === "creature" && !!key;
  return (
    <AnimatePresence>
      {open && (
        <motion.section
          key="creature-page"
          className={styles.page}
          aria-label="Creature inspection"
          initial={
            reduce ? { opacity: 0 } : { opacity: 0, rotateY: -85, x: -12 }
          }
          animate={reduce ? { opacity: 1 } : { opacity: 1, rotateY: 0, x: 0 }}
          exit={
            reduce
              ? { opacity: 0, transition: { duration: 0.15 } }
              : {
                  opacity: 0,
                  rotateY: -60,
                  transition: { duration: 0.18, ease: [0.23, 1, 0.32, 1] },
                }
          }
          transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
          style={{ transformOrigin: "left center", transformPerspective: 1400 }}
        >
          <Corners />
          <Body adapter={adapter} />
        </motion.section>
      )}
    </AnimatePresence>
  );
}

function Corners() {
  const path =
    "M2 38V10C2 5 5 2 10 2h28M8 30c0-12 10-22 22-22M14 20a6 6 0 1 1 6 6";
  return (
    <>
      {(["tl", "tr", "bl", "br"] as const).map((c) => (
        <svg
          key={c}
          className={`${styles.corner} ${styles[c]}`}
          viewBox="0 0 40 40"
          aria-hidden
        >
          <path d={path} />
          <circle cx="6" cy="6" r="2.4" />
        </svg>
      ))}
    </>
  );
}

function Body({ adapter }: { adapter: DataAdapter | null }) {
  const view = useView();
  const key = view.selectedAttacker!;
  const sid = view.selectedSession;
  const attacker = useDomain((s) => s.data.attackers[key]);
  const summary = useDomain((s) => (sid ? s.data.sessions[sid] : undefined));
  const domainEvents = useDomain((s) => s.data.events);
  const [fetched, setFetched] = useState<{
    id: string;
    res?: SessionResponse;
    error?: string;
  } | null>(null);
  const [retry, setRetry] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const heading = useRef<HTMLHeadingElement>(null);

  // full session with events, fetched when the page opens
  useEffect(() => {
    if (!adapter || !sid) return;
    let alive = true;
    adapter
      .session(sid)
      .then((res) => alive && setFetched({ id: sid, res }))
      .catch(
        () =>
          alive && setFetched({ id: sid, error: "Couldn't load this visit." }),
      );
    return () => {
      alive = false;
    };
  }, [adapter, sid, retry]);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    heading.current?.focus({ preventScroll: true });
  }, [key]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") useView.getState().close();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const current = fetched && fetched.id === sid ? fetched : null;
  const loading = !!adapter && !!sid && !current;
  const error = current?.error;
  const session = current?.res?.session ?? summary;

  // fetched events plus anything newer from the live stream
  const events = useMemo(() => {
    const byId = new Map<string, AttackEvent>();
    for (const e of current?.res?.events ?? []) byId.set(e.event_id, e);
    for (const e of Object.values(domainEvents))
      if (e.session_id === sid) byId.set(e.event_id, e);
    return [...byId.values()].sort(eventOrder);
  }, [current, domainEvents, sid]);

  const dossier = useMemo(() => {
    const own = latestOf(events, "dossier");
    if (own) return own;
    return latestOf(
      Object.values(domainEvents)
        .filter((e) => e.type === "dossier" && creatureKey(e) === key)
        .sort(eventOrder),
      "dossier",
    );
  }, [events, domainEvents, key]);

  const profile = attacker?.attacker ?? session?.attacker;
  if (!profile) {
    return (
      <div className={styles.state} role="status">
        {error ? (
          <>
            <p>{error}</p>
            <button type="button" onClick={() => setRetry((n) => n + 1)}>
              <RefreshCw size={14} /> Try again
            </button>
          </>
        ) : (
          <p>Opening the bestiary…</p>
        )}
        <CloseButton />
      </div>
    );
  }

  const maxThreat = attacker?.max_threat ?? profile.threat;
  const source = attacker?.source ?? session?.source ?? "wild";
  const creature = creatureOf(
    profile,
    maxThreat,
    attacker?.visits ?? 1,
    source,
  );
  const geo = attacker?.geo ?? session!.geo;
  const tag = sourceTag(source);
  const reasons = reasonsOf(events);
  const story = session?.story ?? latestOf(events, "story")?.detail.story;
  const tab: Tab = (tabs as string[]).includes(view.subview)
    ? (view.subview as Tab)
    : "replay";
  const kindWord = kindLabel[profile.kind];

  return (
    <div className={styles.inner}>
      <CloseButton />
      <header className={styles.header}>
        <div className={styles.emblem}>
          <Emblem variant={creature.variant} color={creature.color} />
        </div>
        <div className={styles.titles}>
          <p className={styles.eyebrow}>From the bestiary</p>
          <h2 ref={heading} tabIndex={-1} className={styles.title}>
            {creature.label} from {geo.city ?? "an unknown city"}
          </h2>
          <div className={styles.tags}>
            {tag === "simulated" && (
              <span className={styles.tagSim}>simulated</span>
            )}
            {tag === "guest" && <span className={styles.tagGuest}>guest</span>}
            {tag === "mock" && <span className={styles.tagSim}>mock</span>}
          </div>
        </div>
      </header>

      <div className={styles.rule} aria-hidden />

      <section className={styles.facts} aria-label="Facts">
        <div className={styles.confidence}>
          <div
            className={styles.bigNum}
            title={`How sure the classifier is that this is a ${kindWord}`}
          >
            {Math.round(profile.confidence * 100)}%
          </div>
          <div className={styles.confLabel}>
            sure it&apos;s{" "}
            {profile.kind === "unknown" ? "unclassified" : `a ${kindWord}`}
            <span
              className={styles.info}
              tabIndex={0}
              title={`How sure the classifier is that this is a ${kindWord}`}
              aria-label={`How sure the classifier is that this is a ${kindWord}`}
            >
              ?
            </span>
          </div>
          <div className={styles.chips}>
            {reasons.length ? (
              reasons.slice(0, 6).map((r) => (
                <span key={r} className={styles.chip}>
                  {r}
                </span>
              ))
            ) : (
              <span className={styles.chipMuted}>
                {loading ? "reading the evidence…" : "no evidence yet"}
              </span>
            )}
          </div>
        </div>
        <div className={styles.sealBox}>
          <Seal
            color={threatColor[maxThreat]}
            label={threatLabel[maxThreat]}
            title="The highest threat level this visitor reached"
            size={72}
          />
          <span className={styles.sealCap}>threat</span>
        </div>
      </section>

      <div className={styles.badges}>
        <span
          className={styles.badge}
          style={
            { "--b": verdictColor[profile.reputation] } as React.CSSProperties
          }
          title="Web reputation of this visitor"
        >
          {verdictLabel[profile.reputation]}
        </span>
        {profile.family && (
          <span className={styles.badgeFamily} title="Known malware family">
            {profile.family}
          </span>
        )}
      </div>

      <dl className={styles.meta}>
        <div>
          <dt>From</dt>
          <dd>{location(geo)}</dd>
        </div>
        <div>
          <dt>Visits</dt>
          <dd className={styles.num}>{attacker?.visits ?? 1}</dd>
        </div>
        <div>
          <dt>First seen</dt>
          <dd>
            {relativeTime(
              attacker?.first_seen ?? session?.started_at ?? "",
              now,
            )}
          </dd>
        </div>
        <div>
          <dt>Last seen</dt>
          <dd>
            {relativeTime(
              attacker?.last_seen ??
                session?.ended_at ??
                session?.started_at ??
                "",
              now,
            )}
          </dd>
        </div>
      </dl>

      <div className={styles.tabs} role="tablist" aria-label="Creature views">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={tab === t}
            className={tab === t ? styles.tabOn : styles.tab}
            onClick={() => view.view(t)}
          >
            {tabLabel[t]}
            {tab === t && (
              <motion.span layoutId="creature-tab" className={styles.tabInk} />
            )}
          </button>
        ))}
      </div>

      <div className={styles.panel} role="tabpanel">
        {error && (
          <div className={styles.errorRow}>
            <span>{error}</span>
            <button type="button" onClick={() => setRetry((n) => n + 1)}>
              <RefreshCw size={14} /> Try again
            </button>
          </div>
        )}
        {tab === "replay" ? (
          loading ? (
            <p className={styles.empty}>Unrolling the scroll…</p>
          ) : !sid ? (
            <p className={styles.empty}>No visit selected.</p>
          ) : (
            <Replay key={sid} events={events} />
          )
        ) : tab === "story" ? (
          story ? (
            <p className={styles.story}>
              <span className={styles.dropCap}>{story.trim()[0]}</span>
              {story.trim().slice(1)}
            </p>
          ) : (
            <p className={styles.empty}>
              {loading
                ? "Unrolling the scroll…"
                : "No story yet. The chronicler writes one when the visit ends."}
            </p>
          )
        ) : (
          <div className={styles.dossier}>
            <p className={styles.serp}>Live web reputation lookup (SerpApi)</p>
            {dossier ? (
              <>
                <div className={styles.verdict}>
                  <Seal
                    color={verdictColor[profile.reputation]}
                    label={verdictLabel[profile.reputation]}
                    title="What the web says about this visitor"
                    size={78}
                  />
                  <p>{dossier.detail.summary}</p>
                </div>
                {dossier.detail.sources.length > 0 && (
                  <ul className={styles.sources}>
                    {dossier.detail.sources.map((s) => (
                      <li key={s.url}>
                        <a
                          href={s.url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <span className={styles.srcTitle}>{s.title}</span>
                          <span className={styles.srcDomain}>
                            {domainOf(s.url)} <ExternalLink size={11} />
                          </span>
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            ) : (
              <p className={styles.empty}>
                The oracle hasn&apos;t been consulted for this visitor yet.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function CloseButton() {
  return (
    <button
      type="button"
      className={styles.close}
      aria-label="Close creature page"
      onClick={() => useView.getState().close()}
    >
      <X size={18} />
    </button>
  );
}
