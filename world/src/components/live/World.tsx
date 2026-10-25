"use client";
import { Canvas, useFrame } from "@react-three/fiber";
import { Component, useMemo, useState, type ReactNode } from "react";
import { Vector3 } from "three";
import { useReducedMotion } from "framer-motion";
import { useDomain } from "@/lib/store";
import { useView } from "@/lib/view-store";
import { Earth } from "@/components/globe/Earth";
import { Castle } from "@/components/globe/Castle";
import { Creature } from "@/components/globe/Creature";
import { Trails } from "@/components/globe/Trails";
import { Effects } from "@/components/globe/Effects";
import { CameraRig } from "@/components/globe/CameraRig";
import { Tags } from "@/components/globe/Tags";
import { live } from "@/components/globe/shared";
import styles from "@/components/globe/globe.module.css";

// keep the scene light with a lot of traffic
const MAX_CREATURES = 160;
const proj = new Vector3();

function Scene({
  onProjection,
  focus,
  selected,
  hover,
}: {
  onProjection: (x: number, y: number) => void;
  focus: string | null;
  selected: string | null;
  hover: (k: string | null) => void;
}) {
  const attackers = useDomain((s) => s.data.attackers);
  const sessions = useDomain((s) => s.data.sessions);
  const reduced = !!useReducedMotion();
  const shown = useMemo(() => {
    const list = Object.entries(attackers)
      .sort((x, y) => y[1].last_seen.localeCompare(x[1].last_seen))
      .slice(0, MAX_CREATURES);
    if (selected && attackers[selected] && !list.some(([k]) => k === selected))
      list.push([selected, attackers[selected]]);
    return list;
  }, [attackers, selected]);
  useFrame((st) => {
    if (!focus) return;
    const p = live.positions.get(focus);
    if (!p) return;
    proj.copy(p).project(st.camera);
    onProjection(
      ((proj.x + 1) * st.size.width) / 2,
      ((1 - proj.y) * st.size.height) / 2,
    );
  });
  return (
    <>
      <Earth reduced={reduced} />
      <Trails
        attackers={attackers}
        sessions={sessions}
        selected={selected}
        reduced={reduced}
      />
      <Castle reduced={reduced} />
      {shown.map(([k, a]) => (
        <Creature
          key={k}
          k={k}
          a={a}
          session={sessions[a.latest_session_id]}
          selected={k === selected}
          reduced={reduced}
          onHover={hover}
        />
      ))}
      <Effects reduced={reduced} />
      <CameraRig focus={focus} reduced={reduced} />
    </>
  );
}

class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <p className={styles.error}>
        The 3D globe could not load. You can still read every encounter in the
        chronicle. Reload to try again.
      </p>
    ) : (
      this.props.children
    );
  }
}

export default function World({
  onProjection,
}: {
  onProjection: (x: number, y: number) => void;
}) {
  const surface = useView((s) => s.surface);
  const selectedAttacker = useView((s) => s.selectedAttacker);
  const selected = surface === "creature" ? selectedAttacker : null;
  const [hovered, setHovered] = useState<string | null>(null);
  return (
    <div className={styles.root}>
      <Boundary>
        <Canvas
          className={styles.canvas}
          orthographic
          camera={{ position: [-3.2, 3.2, 6.4], zoom: 175, near: 0.1, far: 60 }}
          dpr={[1, 1.5]}
          gl={{ antialias: true, alpha: true }}
          onPointerMissed={() => setHovered(null)}
          fallback={
            <p className={styles.error}>
              WebGL is not available here. The chronicle still lists every
              encounter.
            </p>
          }
        >
          <Scene
            onProjection={onProjection}
            focus={selected}
            selected={selected}
            hover={setHovered}
          />
        </Canvas>
        <Tags selected={selected} hovered={hovered} />
      </Boundary>
    </div>
  );
}
