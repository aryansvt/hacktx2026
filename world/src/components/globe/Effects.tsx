"use client";
// three.js objects are mutated per frame by design
/* eslint-disable react-hooks/immutability */
import { useEffect, useMemo, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import {
  AdditiveBlending,
  BufferGeometry,
  Color,
  DoubleSide,
  Float32BufferAttribute,
  Mesh,
  MeshBasicMaterial,
  Quaternion,
  RingGeometry,
  Sprite,
  SpriteMaterial,
  Vector3,
  type Group,
} from "three";
import { bus } from "@/lib/bus";
import { creatureKey } from "@/lib/domain";
import { creatureOf } from "@/lib/creatures";
import type { AttackEvent } from "@/lib/contracts";
import { GLOBE_R, hash01, toXYZ } from "./geo";
import {
  castlePos,
  castleUp,
  glowTexture,
  live,
  palette,
  runeTexture,
  runes,
} from "./shared";

type Kind = "spark" | "flash" | "rune" | "trip" | "puff";
interface Fx {
  kind: Kind;
  start: number;
  life: number;
  pos: Vector3;
  up: Vector3;
  color: Color;
  size: number;
  drift: number;
}
interface Ripple {
  start: number;
  life: number;
  pos: Vector3;
  color: Color;
}

const SPRITES = 48;
const RIPPLES = 16;
const HEAT = 200;

export function Effects({ reduced }: { reduced: boolean }) {
  const group = useRef<Group>(null!);
  const pool = useMemo(
    () =>
      Array.from({ length: SPRITES }, () => {
        const s = new Sprite(
          new SpriteMaterial({
            map: glowTexture(),
            transparent: true,
            blending: AdditiveBlending,
            depthWrite: false,
          }),
        );
        s.visible = false;
        return s;
      }),
    [],
  );
  const rings = useMemo(
    () =>
      Array.from({ length: RIPPLES }, () => {
        const m = new Mesh(
          new RingGeometry(0.8, 1, 40),
          new MeshBasicMaterial({
            transparent: true,
            blending: AdditiveBlending,
            depthWrite: false,
            side: DoubleSide,
          }),
        );
        m.visible = false;
        return m;
      }),
    [],
  );
  const heatGeo = useMemo(() => {
    const g = new BufferGeometry();
    g.setAttribute(
      "position",
      new Float32BufferAttribute(new Float32Array(HEAT * 3), 3),
    );
    g.setAttribute(
      "color",
      new Float32BufferAttribute(new Float32Array(HEAT * 3), 3),
    );
    g.setDrawRange(0, 0);
    return g;
  }, []);
  const fx = useRef<(Fx | null)[]>(Array(SPRITES).fill(null));
  const ripples = useRef<(Ripple | null)[]>(Array(RIPPLES).fill(null));
  const heat = useRef<{ pos: Vector3; born: number }[]>([]);
  const clock = useRef(0);
  const dpr = useThree((s) => s.viewport.dpr);

  useEffect(() => {
    const g = group.current;
    pool.forEach((s) => g.add(s));
    rings.forEach((r) => g.add(r));
    return () => {
      pool.forEach((s) => {
        g.remove(s);
        s.material.dispose();
      });
      rings.forEach((r) => {
        g.remove(r);
        r.geometry.dispose();
        r.material.dispose();
      });
      heatGeo.dispose();
    };
  }, [pool, rings, heatGeo]);

  useEffect(() => {
    const spawn = (f: Omit<Fx, "start">) => {
      const list = fx.current;
      let i = list.findIndex((x) => !x);
      // pool full: reuse the oldest
      if (i < 0)
        i = list.reduce((o, x, j) => (x!.start < list[o]!.start ? j : o), 0);
      list[i] = { ...f, start: clock.current };
      const s = pool[i];
      s.material.map =
        f.kind === "rune"
          ? runeTexture(
              runes[
                Math.floor(hash01(String(clock.current), 5) * runes.length)
              ],
            )
          : glowTexture();
      s.material.needsUpdate = true;
      s.material.color.copy(f.color);
    };
    const ripple = (pos: Vector3, color: Color) => {
      const list = ripples.current;
      let i = list.findIndex((x) => !x);
      if (i < 0)
        i = list.reduce((o, x, j) => (x!.start < list[o]!.start ? j : o), 0);
      list[i] = { start: clock.current, life: 2.2, pos, color };
      const r = rings[i];
      r.position.copy(pos).multiplyScalar(1.003);
      r.quaternion.copy(
        new Quaternion().setFromUnitVectors(
          new Vector3(0, 0, 1),
          pos.clone().normalize(),
        ),
      );
      r.material.color.copy(color);
    };
    const gate = () => castlePos.clone().addScaledVector(castleUp, 0.04);
    const where = (e: AttackEvent) =>
      live.positions.get(creatureKey(e))?.clone() ??
      new Vector3(...toXYZ(e.geo.lat, e.geo.lon, GLOBE_R + 0.03));
    return bus.on((e) => {
      const color = new Color(creatureOf(e.attacker, e.attacker.threat).color);
      switch (e.type) {
        case "session_start":
          ripple(new Vector3(...toXYZ(e.geo.lat, e.geo.lon, GLOBE_R)), color);
          break;
        case "login_fail":
          live.pulse = 1;
          spawn({
            kind: "spark",
            life: 0.7,
            pos: gate(),
            up: castleUp,
            color: new Color("#ff5a3c"),
            size: 0.16,
            drift: 0.06,
          });
          break;
        case "login_success":
          live.flash = 1;
          spawn({
            kind: "flash",
            life: 1.2,
            pos: gate(),
            up: castleUp,
            color: new Color(palette.goldLight),
            size: 0.5,
            drift: 0,
          });
          break;
        case "command":
          spawn({
            kind: "rune",
            life: 2.4,
            pos: castlePos.clone().addScaledVector(castleUp, 0.2),
            up: castleUp,
            color: new Color("#ffffff"),
            size: 0.09,
            drift: 0.4,
          });
          break;
        case "tripwire":
          spawn({
            kind: "trip",
            life: 1.1,
            pos: where(e),
            up: where(e).normalize(),
            color: new Color(palette.purple),
            size: 0.3,
            drift: 0,
          });
          break;
        case "classified":
          for (let i = 0; i < 4; i++) {
            const p = where(e);
            p.x += (hash01(e.event_id, i) - 0.5) * 0.04;
            p.z += (hash01(e.event_id, i + 9) - 0.5) * 0.04;
            spawn({
              kind: "puff",
              life: 1.6 + i * 0.2,
              pos: p,
              up: p.clone().normalize(),
              color: new Color(palette.gold),
              size: 0.12,
              drift: 0.08,
            });
          }
          break;
        case "session_end": {
          const h = heat.current;
          h.push({
            pos: new Vector3(...toXYZ(e.geo.lat, e.geo.lon, GLOBE_R + 0.008)),
            born: clock.current,
          });
          if (h.length > HEAT) h.shift();
          break;
        }
      }
    });
  }, [pool, rings]);

  useFrame((_, dt) => {
    clock.current += dt;
    const now = clock.current;
    fx.current.forEach((f, i) => {
      const s = pool[i];
      if (!f) return;
      const k = (now - f.start) / f.life;
      if (k >= 1) {
        fx.current[i] = null;
        s.visible = false;
        return;
      }
      s.visible = true;
      const ease = 1 - Math.pow(1 - k, 3);
      s.position
        .copy(f.pos)
        .addScaledVector(f.up, reduced ? 0 : f.drift * ease);
      let size = f.size,
        alpha = 1 - k;
      if (!reduced) {
        if (f.kind === "spark") size *= 0.6 + ease;
        if (f.kind === "flash") {
          size *= 0.4 + ease;
          alpha = Math.pow(1 - k, 2);
        }
        if (f.kind === "trip") size *= 0.5 + Math.sin(k * Math.PI) * 0.9;
        if (f.kind === "puff") size *= 0.5 + ease * 1.4;
        if (f.kind === "rune") alpha = Math.min(1, k * 6) * (1 - k);
      }
      s.scale.setScalar(size);
      s.material.opacity = alpha * (f.kind === "puff" ? 0.6 : 1);
    });
    ripples.current.forEach((r, i) => {
      const m = rings[i];
      if (!r) return;
      const k = (now - r.start) / r.life;
      if (k >= 1) {
        ripples.current[i] = null;
        m.visible = false;
        return;
      }
      m.visible = true;
      m.scale.setScalar(reduced ? 0.12 : 0.02 + k * 0.2);
      m.material.opacity = (1 - k) * 0.9;
    });
    // heat: each finished visit leaves a glow that settles to a faint ember
    const h = heat.current;
    const P = heatGeo.attributes.position.array as Float32Array,
      C = heatGeo.attributes.color.array as Float32Array;
    for (let i = 0; i < h.length; i++) {
      const age = now - h[i].born;
      const k = 0.18 + 0.82 * Math.exp(-age / 40);
      P.set([h[i].pos.x, h[i].pos.y, h[i].pos.z], i * 3);
      C[i * 3] = 1 * k;
      C[i * 3 + 1] = 0.55 * k;
      C[i * 3 + 2] = 0.2 * k;
    }
    heatGeo.setDrawRange(0, h.length);
    heatGeo.attributes.position.needsUpdate = true;
    heatGeo.attributes.color.needsUpdate = true;
  });

  return (
    <group ref={group}>
      <points geometry={heatGeo} frustumCulled={false}>
        <pointsMaterial
          vertexColors
          size={26 * dpr}
          sizeAttenuation={false}
          map={glowTexture()}
          transparent
          blending={AdditiveBlending}
          depthWrite={false}
        />
      </points>
    </group>
  );
}
