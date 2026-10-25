"use client";
// three.js objects are mutated per frame by design
/* eslint-disable react-hooks/immutability */
import { memo, useEffect, useMemo, useRef, type RefObject } from "react";
import { useFrame, type ThreeEvent } from "@react-three/fiber";
import {
  AdditiveBlending,
  Color,
  DoubleSide,
  Matrix4,
  MeshBasicMaterial,
  MeshStandardMaterial,
  SpriteMaterial,
  Vector3,
  type Group,
  type Mesh,
  type Sprite,
} from "three";
import type { AttackerSummary, SessionSummary } from "@/lib/contracts";
import { creatureOf, type Variant } from "@/lib/creatures";
import { screen } from "@/lib/screen";
import { useView } from "@/lib/view-store";
import { GLOBE_R, gateSlot, hash01, progressFor, slerp, toXYZ, type V3 } from "./geo";
import { castlePos, castleUp, glowTexture, live, palette } from "./shared";

const BASE = 0.056;
const elite = new Set<Variant>(["stone-golem", "witch", "cursed-fae"]);

interface Mats {
  main: MeshStandardMaterial;
  dark: MeshStandardMaterial;
  glow: MeshBasicMaterial;
  wing: MeshBasicMaterial;
  eye: MeshBasicMaterial;
  ring: MeshBasicMaterial;
  sprite: SpriteMaterial;
  all: { m: { opacity: number; transparent: boolean }; base: number }[];
}

function makeMats(variant: Variant, color: string, source: string): Mats {
  const c = new Color(color);
  const isElite = elite.has(variant);
  // elites read darker, with red eyes and a red aura
  const body = isElite ? c.clone().multiplyScalar(0.55) : c;
  const main = new MeshStandardMaterial({
    color: variant === "shadow" ? new Color("#2a2c38") : body,
    emissive: variant === "shadow" ? new Color("#11131c") : body,
    emissiveIntensity: variant === "slime" || variant === "fae" ? 0.7 : 0.35,
    roughness: 0.7,
    transparent: true,
    opacity: variant === "slime" ? 0.78 : variant === "shadow" ? 0.72 : 1,
  });
  const dark = new MeshStandardMaterial({
    color: isElite ? new Color("#1d1420") : c.clone().multiplyScalar(0.6),
    emissive: c.clone().multiplyScalar(0.15),
    roughness: 0.8,
    transparent: true,
  });
  const glow = new MeshBasicMaterial({
    color: c.clone().lerp(new Color("#ffffff"), 0.35),
    transparent: true,
    blending: AdditiveBlending,
    depthWrite: false,
  });
  const wing = new MeshBasicMaterial({
    color: c.clone().lerp(new Color("#ffffff"), 0.4),
    transparent: true,
    opacity: 0.55,
    side: DoubleSide,
    blending: AdditiveBlending,
    depthWrite: false,
  });
  const eye = new MeshBasicMaterial({
    color: isElite || variant === "dragon" ? "#ff4a2a" : "#fff6d6",
    transparent: true,
  });
  const ring = new MeshBasicMaterial({
    color:
      source === "guest"
        ? palette.goldLight
        : isElite || variant === "dragon"
          ? "#ff3b24"
          : color,
    transparent: true,
    opacity: 0.6,
    side: DoubleSide,
    blending: AdditiveBlending,
    depthWrite: false,
  });
  const sprite = new SpriteMaterial({
    map: glowTexture(),
    color: source === "guest" ? new Color(palette.goldLight) : c,
    transparent: true,
    opacity: 0.85,
    blending: AdditiveBlending,
    depthWrite: false,
  });
  const all = [main, dark, glow, wing, eye, ring, sprite].map((m) => ({
    m,
    base: m.opacity,
  }));
  return { main, dark, glow, wing, eye, ring, sprite, all };
}

type Wings = RefObject<Mesh[]>;

function Body({ variant, m, wings }: { variant: Variant; m: Mats; wings: Wings }) {
  const wing = (i: number) => (el: Mesh | null) => {
    if (el) wings.current[i] = el;
  };
  switch (variant) {
    case "golem":
    case "stone-golem":
      return (
        <>
          <mesh position={[0, 0.75, 0]} material={m.main}>
            <boxGeometry args={[1, 0.9, 0.7]} />
          </mesh>
          <mesh position={[0, 1.45, 0]} material={m.main}>
            <boxGeometry args={[0.6, 0.5, 0.5]} />
          </mesh>
          {[-1, 1].map((s) => (
            <mesh key={s} position={[s * 0.68, 0.72, 0]} material={m.dark}>
              <boxGeometry args={[0.32, 0.85, 0.34]} />
            </mesh>
          ))}
          {[-1, 1].map((s) => (
            <mesh key={`l${s}`} position={[s * 0.26, 0.16, 0]} material={m.dark}>
              <boxGeometry args={[0.32, 0.34, 0.34]} />
            </mesh>
          ))}
          {[-1, 1].map((s) => (
            <mesh key={`e${s}`} position={[s * 0.14, 1.5, 0.26]} material={m.eye}>
              <boxGeometry args={[0.1, 0.08, 0.02]} />
            </mesh>
          ))}
          {variant === "stone-golem" && (
            <mesh position={[0, 1.78, 0]} material={m.dark}>
              <coneGeometry args={[0.32, 0.3, 4]} />
            </mesh>
          )}
        </>
      );
    case "mage":
    case "witch":
      return (
        <>
          <mesh position={[0, 0.55, 0]} material={m.main}>
            <coneGeometry args={[0.55, 1.1, 12]} />
          </mesh>
          <mesh position={[0, 1.22, 0]} material={m.dark}>
            <sphereGeometry args={[0.24, 12, 12]} />
          </mesh>
          <mesh position={[0, 1.42, 0]} material={m.main}>
            <cylinderGeometry args={[0.46, 0.46, 0.05, 16]} />
          </mesh>
          <mesh
            position={[variant === "witch" ? 0.1 : 0, 1.82, 0]}
            rotation={[0, 0, variant === "witch" ? -0.35 : 0]}
            material={m.main}
          >
            <coneGeometry args={[0.3, 0.8, 12]} />
          </mesh>
          <mesh position={[0.52, 0.75, 0.1]} material={m.dark}>
            <cylinderGeometry args={[0.035, 0.035, 1.5, 6]} />
          </mesh>
          <mesh position={[0.52, 1.55, 0.1]} material={m.glow}>
            <sphereGeometry args={[0.12, 10, 10]} />
          </mesh>
          {[-1, 1].map((s) => (
            <mesh key={s} position={[s * 0.08, 1.24, 0.21]} material={m.eye}>
              <sphereGeometry args={[0.035, 6, 6]} />
            </mesh>
          ))}
        </>
      );
    case "fae":
    case "cursed-fae":
      return (
        <>
          <mesh position={[0, 0.85, 0]} material={m.main}>
            <capsuleGeometry args={[0.2, 0.35, 4, 10]} />
          </mesh>
          <mesh position={[0, 1.32, 0]} material={m.main}>
            <sphereGeometry args={[0.2, 12, 12]} />
          </mesh>
          <mesh position={[0, 0.9, 0]} material={m.glow} scale={0.9}>
            <sphereGeometry args={[0.42, 12, 12]} />
          </mesh>
          {[-1, 1].map((s, i) => (
            <group key={s} position={[s * 0.12, 1.05, -0.1]}>
              <mesh ref={wing(i)} material={m.wing}>
                <circleGeometry args={[0.5, 3]} />
              </mesh>
            </group>
          ))}
          {[-1, 1].map((s) => (
            <mesh key={`e${s}`} position={[s * 0.07, 1.35, 0.18]} material={m.eye}>
              <sphereGeometry args={[0.03, 6, 6]} />
            </mesh>
          ))}
        </>
      );
    case "shadow":
      return (
        <>
          <mesh position={[0, 0.75, 0]} scale={[1, 1.35, 1]} material={m.main}>
            <sphereGeometry args={[0.55, 14, 14]} />
          </mesh>
          <mesh position={[0, 0.2, 0]} rotation={[Math.PI, 0, 0]} material={m.main}>
            <coneGeometry args={[0.5, 0.5, 10]} />
          </mesh>
          {[-1, 1].map((s) => (
            <mesh key={s} position={[s * 0.17, 1.0, 0.48]} material={m.eye}>
              <sphereGeometry args={[0.07, 8, 8]} />
            </mesh>
          ))}
        </>
      );
    case "slime":
      return (
        <>
          <mesh position={[0, 0.4, 0]} scale={[1, 0.62, 1]} material={m.main}>
            <sphereGeometry args={[0.65, 16, 16]} />
          </mesh>
          <mesh position={[0, 0.42, 0]} scale={[0.6, 0.38, 0.6]} material={m.glow}>
            <sphereGeometry args={[0.65, 12, 12]} />
          </mesh>
          {[-1, 1].map((s) => (
            <mesh key={s} position={[s * 0.18, 0.55, 0.52]} material={m.eye}>
              <sphereGeometry args={[0.07, 8, 8]} />
            </mesh>
          ))}
        </>
      );
    case "dragon":
      return (
        <>
          <mesh position={[0, 0.9, 0]} scale={[0.55, 0.5, 1.25]} material={m.main}>
            <sphereGeometry args={[0.6, 14, 14]} />
          </mesh>
          <mesh position={[0, 1.25, 0.85]} rotation={[Math.PI / 2.6, 0, 0]} material={m.main}>
            <coneGeometry args={[0.2, 0.75, 10]} />
          </mesh>
          <mesh position={[0, 1.5, 1.15]} material={m.dark}>
            <boxGeometry args={[0.28, 0.22, 0.4]} />
          </mesh>
          <mesh position={[0, 0.85, -1.05]} rotation={[-Math.PI / 2, 0, 0]} material={m.main}>
            <coneGeometry args={[0.18, 0.9, 8]} />
          </mesh>
          {[-1, 1].map((s, i) => (
            <group key={s} position={[s * 0.25, 1.1, 0]}>
              <mesh
                ref={wing(i)}
                position={[s * 0.7, 0, 0]}
                rotation={[-Math.PI / 2, 0, 0]}
                material={m.wing}
              >
                <planeGeometry args={[1.4, 0.9]} />
              </mesh>
            </group>
          ))}
          {[-1, 1].map((s) => (
            <mesh key={`e${s}`} position={[s * 0.1, 1.58, 1.33]} material={m.eye}>
              <sphereGeometry args={[0.04, 6, 6]} />
            </mesh>
          ))}
        </>
      );
  }
}

const up = new Vector3(),
  fwd = new Vector3(),
  right = new Vector3(),
  tmp = new Vector3(),
  basis = new Matrix4();

export const Creature = memo(function Creature({
  k,
  a,
  session,
  selected,
  reduced,
  onHover,
}: {
  k: string;
  a: AttackerSummary;
  session: SessionSummary | undefined;
  selected: boolean;
  reduced: boolean;
  onHover: (k: string | null) => void;
}) {
  const c = creatureOf(a.attacker, a.max_threat, a.visits);
  const m = useMemo(
    () => makeMats(c.variant, c.color, a.source),
    [c.variant, c.color, a.source],
  );
  useEffect(
    () => () => {
      for (const { m: x } of m.all) (x as MeshBasicMaterial).dispose();
    },
    [m],
  );
  const root = useRef<Group>(null!);
  const body = useRef<Group>(null!);
  const halo = useRef<Mesh>(null!);
  const glow = useRef<Sprite>(null!);
  const wings = useRef<Mesh[]>([]);
  const origin = useMemo<V3>(() => toXYZ(a.geo.lat, a.geo.lon), [a.geo.lat, a.geo.lon]);
  const slot = useMemo(() => gateSlot(k, castlePos.toArray() as V3), [k]);
  const state = useRef({ prog: -1, fade: 1, sel: 0 });
  const phase = useMemo(() => hash01(k, 3) * Math.PI * 2, [k]);
  const status = session?.status ?? "ended";
  const started = session ? Date.parse(session.started_at) : 0;
  const dragon = c.variant === "dragon";
  const size = BASE * c.scale * (dragon ? 1.7 : 1);
  const ringed = elite.has(c.variant) || dragon || a.source === "guest";

  useFrame((st, dt) => {
    const s = state.current;
    const t = st.clock.elapsedTime;
    const target = progressFor(status, Date.now() - started);
    if (s.prog < 0 || reduced) s.prog = target;
    else s.prog += (target - s.prog) * Math.min(1, dt * 0.9);
    const dir = slerp(origin, slot, Math.min(1, Math.max(0, s.prog)));
    up.set(dir[0], dir[1], dir[2]);
    let alt = 0.006;
    // facing: toward the gate while marching, toward the castle once there
    tmp.set(slot[0], slot[1], slot[2]).sub(up);
    if (s.prog > 0.98 || tmp.lengthSq() < 1e-5) tmp.copy(castlePos).sub(root.current.position);
    if (dragon) {
      alt = 0.12;
      if (s.prog > 0.95) {
        // circle the castle
        const ang = (reduced ? 0 : t * 0.35) + phase;
        right.set(1, 0, 0).cross(castleUp).normalize();
        fwd.copy(castleUp).cross(right);
        up.copy(castleUp)
          .multiplyScalar(GLOBE_R)
          .addScaledVector(right, Math.cos(ang) * 0.42)
          .addScaledVector(fwd, Math.sin(ang) * 0.42)
          .normalize();
        tmp.copy(right).multiplyScalar(-Math.sin(ang)).addScaledVector(fwd, Math.cos(ang));
        alt = 0.22;
      }
    }
    const bob = reduced ? 0 : Math.abs(Math.sin(t * 6 + phase)) * 0.01 * (dragon ? 2 : 1);
    root.current.position.copy(up).multiplyScalar(GLOBE_R + alt + bob);
    // build an upright basis on the surface
    fwd.copy(tmp).addScaledVector(up, -tmp.dot(up));
    if (fwd.lengthSq() < 1e-8) fwd.set(0, 0, 1).addScaledVector(up, -up.z);
    fwd.normalize();
    right.copy(up).cross(fwd).normalize();
    basis.makeBasis(right, up, fwd);
    root.current.quaternion.setFromRotationMatrix(basis);

    // little march sway and wing flaps
    if (!reduced) {
      body.current.rotation.z = Math.sin(t * 6 + phase) * 0.12;
      if (c.variant === "slime")
        body.current.scale.set(1 + Math.sin(t * 5 + phase) * 0.08, 1 - Math.sin(t * 5 + phase) * 0.1, 1);
      const w = wings.current;
      if (w.length === 2) {
        const f = Math.sin(t * (dragon ? 5 : 14) + phase) * (dragon ? 0.5 : 0.6);
        if (dragon) {
          w[0].parent!.rotation.z = f;
          w[1].parent!.rotation.z = -f;
        } else {
          w[0].rotation.set(0, 0.6 + f, 0.6);
          w[1].rotation.set(0, -0.6 - f, -0.6);
        }
      }
    }

    // ended creatures dim back at their origin
    const fadeTo = status === "ended" ? 0.38 : 1;
    s.fade += (fadeTo - s.fade) * Math.min(1, dt * 2);
    s.sel += ((selected ? 1 : 0) - s.sel) * Math.min(1, dt * 8);
    for (const { m: x, base } of m.all) x.opacity = base * s.fade;
    root.current.scale.setScalar(size * (1 + s.sel * 0.45));
    if (halo.current) {
      const p = reduced ? 0.5 : 0.5 + Math.sin(t * 3 + phase) * 0.5;
      halo.current.scale.setScalar(1 + p * 0.25 + s.sel * 0.4);
    }
    glow.current.scale.setScalar(2.4 + s.sel * 1.6);

    // screen anchor and visibility
    const cam = st.camera;
    const visible = up.dot(tmp.copy(cam.position).normalize()) > 0.02;
    root.current.visible = visible || s.sel > 0.01;
    live.visible.set(k, visible);
    let pos = live.positions.get(k);
    if (!pos) live.positions.set(k, (pos = new Vector3()));
    pos.copy(root.current.position);
    tmp.copy(root.current.position).addScaledVector(up, size * 1.2).project(cam);
    let sp = screen.creatures.get(k);
    if (!sp) screen.creatures.set(k, (sp = { x: 0, y: 0, visible: false }));
    sp.x = ((tmp.x + 1) * st.size.width) / 2;
    sp.y = ((1 - tmp.y) * st.size.height) / 2;
    sp.visible = visible;
  });

  useEffect(
    () => () => {
      screen.creatures.delete(k);
      live.positions.delete(k);
      live.visible.delete(k);
    },
    [k],
  );

  const over = (e: ThreeEvent<PointerEvent>) => {
    if (!live.visible.get(k)) return;
    e.stopPropagation();
    onHover(k);
    document.body.style.cursor = "pointer";
  };
  const out = () => {
    onHover(null);
    document.body.style.cursor = "";
  };
  return (
    <group ref={root}>
      <sprite ref={glow} position={[0, 0.8, 0]} material={m.sprite} />
      {ringed && (
        <mesh ref={halo} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.05, 0]} material={m.ring}>
          <ringGeometry args={[0.85, 1.05, 32]} />
        </mesh>
      )}
      {selected && (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.04, 0]}>
          <ringGeometry args={[1.25, 1.42, 40]} />
          <meshBasicMaterial
            color={palette.goldLight}
            transparent
            opacity={0.9}
            blending={AdditiveBlending}
            depthWrite={false}
            side={DoubleSide}
          />
        </mesh>
      )}
      <group ref={body}>
        <Body variant={c.variant} m={m} wings={wings} />
      </group>
      {/* invisible, generous hit target */}
      <mesh
        position={[0, 0.9, 0]}
        onPointerOver={over}
        onPointerOut={out}
        onClick={(e) => {
          if (!live.visible.get(k)) return;
          e.stopPropagation();
          useView.getState().select(k, a.latest_session_id, "map");
        }}
      >
        <sphereGeometry args={[1.5, 8, 8]} />
        <meshBasicMaterial transparent opacity={0} depthWrite={false} colorWrite={false} />
      </mesh>
    </group>
  );
});
