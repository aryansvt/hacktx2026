"use client";
// three.js objects are mutated per frame by design
/* eslint-disable react-hooks/immutability */
import { useEffect, useMemo, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import {
  AdditiveBlending,
  BufferGeometry,
  Color,
  Float32BufferAttribute,
  type Points,
} from "three";
import type { AttackerSummary, SessionSummary } from "@/lib/contracts";
import { creatureOf } from "@/lib/creatures";
import { arcPoint, hash01, toXYZ, type V3 } from "./geo";
import { castlePos, dotTexture, palette } from "./shared";

const MAX_ARCS = 60;
const SEG = 40;
const CRUMBS = 7;

interface Arc {
  pts: Float32Array; // (SEG + 1) * 3
  active: boolean;
}

export function Trails({
  attackers,
  sessions,
  selected,
  reduced,
}: {
  attackers: Record<string, AttackerSummary>;
  sessions: Record<string, SessionSummary>;
  selected: string | null;
  reduced: boolean;
}) {
  // newest attackers get trails, plus the selected one
  const arcs = useMemo(() => {
    const list = Object.entries(attackers)
      .sort((x, y) => y[1].last_seen.localeCompare(x[1].last_seen))
      .slice(0, MAX_ARCS);
    if (selected && attackers[selected] && !list.some(([k]) => k === selected))
      list.push([selected, attackers[selected]]);
    const castle = castlePos.toArray() as V3;
    return list.map(([k, a]) => {
      const o = toXYZ(a.geo.lat, a.geo.lon);
      const pts = new Float32Array((SEG + 1) * 3);
      for (let i = 0; i <= SEG; i++) {
        const p = arcPoint(o, castle, i / SEG, 2.004);
        pts.set(p, i * 3);
      }
      const status = sessions[a.latest_session_id]?.status ?? "ended";
      return {
        k,
        pts,
        active: status !== "ended",
        color: creatureOf(a.attacker, a.max_threat, a.visits).color,
      } as Arc & { k: string; color: string };
    });
  }, [attackers, sessions, selected]);

  const lines = useMemo(() => {
    const pos: number[] = [],
      col: number[] = [];
    const c = new Color();
    for (const arc of arcs) {
      const sel = arc.k === selected;
      c.set(arc.color).multiplyScalar(sel ? 1.3 : arc.active ? 0.75 : 0.32);
      for (let i = 0; i < SEG; i++) {
        pos.push(...arc.pts.subarray(i * 3, i * 3 + 6));
        // fade the trail in near the origin and out at the castle
        const f = Math.sin(((i + 0.5) / SEG) * Math.PI) * 0.6 + 0.4;
        col.push(c.r * f, c.g * f, c.b * f, c.r * f, c.g * f, c.b * f);
      }
    }
    const g = new BufferGeometry();
    g.setAttribute("position", new Float32BufferAttribute(pos, 3));
    g.setAttribute("color", new Float32BufferAttribute(col, 3));
    return g;
  }, [arcs, selected]);
  useEffect(() => () => lines.dispose(), [lines]);

  const crumbGeo = useMemo(() => {
    const n = (MAX_ARCS + 1) * CRUMBS;
    const g = new BufferGeometry();
    g.setAttribute(
      "position",
      new Float32BufferAttribute(new Float32Array(n * 3), 3),
    );
    g.setAttribute(
      "color",
      new Float32BufferAttribute(new Float32Array(n * 3), 3),
    );
    return g;
  }, []);
  useEffect(() => () => crumbGeo.dispose(), [crumbGeo]);
  const crumbs = useRef<Points>(null!);
  const dpr = useThree((s) => s.viewport.dpr);
  const gold = useMemo(() => new Color(palette.goldLight), []);
  const goldDeep = useMemo(() => new Color(palette.gold), []);

  useFrame((st) => {
    const t = st.clock.elapsedTime;
    const pos = crumbGeo.attributes.position as Float32BufferAttribute;
    const col = crumbGeo.attributes.color as Float32BufferAttribute;
    const P = pos.array as Float32Array,
      C = col.array as Float32Array;
    let n = 0;
    for (let a = 0; a < arcs.length; a++) {
      const arc = arcs[a];
      const count = arc.active || arc.k === selected ? CRUMBS : 3;
      const speed = arc.active ? 0.07 : 0.025;
      for (let j = 0; j < count; j++) {
        const seed = hash01(arc.k, j + 20);
        const u = reduced
          ? (j + 0.5) / count
          : (seed + j / count + t * speed) % 1;
        const f = u * SEG;
        const i = Math.min(SEG - 1, Math.floor(f)),
          w = f - i;
        const b = i * 3;
        P[n * 3] = arc.pts[b] + (arc.pts[b + 3] - arc.pts[b]) * w;
        P[n * 3 + 1] = arc.pts[b + 1] + (arc.pts[b + 4] - arc.pts[b + 1]) * w;
        P[n * 3 + 2] = arc.pts[b + 2] + (arc.pts[b + 5] - arc.pts[b + 2]) * w;
        // sparkle: brightness flickers per crumb, fades at both ends
        const tw = reduced ? 0.8 : 0.55 + 0.45 * Math.sin(t * 7 + seed * 40);
        const edge = Math.sin(u * Math.PI);
        const k = tw * edge * (arc.active ? 1 : 0.5);
        const c = j % 2 ? gold : goldDeep;
        C[n * 3] = c.r * k;
        C[n * 3 + 1] = c.g * k;
        C[n * 3 + 2] = c.b * k;
        n++;
      }
    }
    crumbGeo.setDrawRange(0, n);
    pos.needsUpdate = true;
    col.needsUpdate = true;
  });

  return (
    <>
      <lineSegments geometry={lines}>
        <lineBasicMaterial
          vertexColors
          transparent
          opacity={0.75}
          blending={AdditiveBlending}
          depthWrite={false}
        />
      </lineSegments>
      <points ref={crumbs} geometry={crumbGeo} frustumCulled={false}>
        <pointsMaterial
          vertexColors
          size={5.5 * dpr}
          sizeAttenuation={false}
          map={dotTexture()}
          transparent
          blending={AdditiveBlending}
          depthWrite={false}
        />
      </points>
    </>
  );
}
