"use client";
import { useEffect, useRef, useState } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import type { OrthographicCamera } from "three";
import { easeInOut, slerp, type V3 } from "./geo";
import { live } from "./shared";

// globe is 4 units wide; about 700px tall at 1080p, smaller on narrow screens
export const baseZoom = (w: number, h: number) =>
  Math.min(h * 0.162, w * 0.19);

interface Flight {
  from: V3;
  to: () => V3 | null;
  zoomFrom: number;
  zoomTo: number;
  start: number;
}

export function CameraRig({
  focus,
  reduced,
}: {
  focus: string | null;
  reduced: boolean;
}) {
  const size = useThree((s) => s.size);
  const get = useThree((s) => s.get);
  const [interacted, setInteracted] = useState(false);
  const base = baseZoom(size.width, size.height);
  const flight = useRef<Flight | null>(null);
  const home = useRef<{ dir: V3; zoom: number } | null>(null);
  const clock = useRef(0);

  useEffect(() => {
    const cam = get().camera as OrthographicCamera;
    cam.zoom = baseZoom(size.width, size.height);
    cam.updateProjectionMatrix();
  }, [get, size.width, size.height]);

  useEffect(() => {
    const cam = get().camera as OrthographicCamera;
    const dir = cam.position.clone().normalize().toArray() as V3;
    if (focus) {
      if (!home.current) home.current = { dir, zoom: cam.zoom };
      flight.current = {
        from: dir,
        to: () => {
          const p = live.positions.get(focus);
          return p ? (p.clone().normalize().toArray() as V3) : null;
        },
        zoomFrom: cam.zoom,
        zoomTo: Math.max(cam.zoom, baseZoom(get().size.width, get().size.height) * 1.35),
        start: clock.current,
      };
    } else if (home.current) {
      const h = home.current;
      home.current = null;
      flight.current = {
        from: dir,
        to: () => h.dir,
        zoomFrom: cam.zoom,
        zoomTo: h.zoom,
        start: clock.current,
      };
    }
  }, [focus, get]);

  useFrame((st, dt) => {
    clock.current += dt;
    const f = flight.current;
    if (!f) return;
    const controls = st.controls as unknown as { enabled: boolean; update: () => void } | null;
    const cam = st.camera as OrthographicCamera;
    const to = f.to();
    if (!to) {
      flight.current = null;
      return;
    }
    const k = reduced ? 1 : Math.min(1, (clock.current - f.start) / 1.1);
    const e = easeInOut(k);
    const d = cam.position.length();
    const dir = slerp(f.from, to, e);
    cam.position.set(dir[0] * d, dir[1] * d, dir[2] * d);
    cam.zoom = f.zoomFrom + (f.zoomTo - f.zoomFrom) * e;
    cam.lookAt(0, 0, 0);
    cam.updateProjectionMatrix();
    if (controls) controls.enabled = k >= 1;
    if (k >= 1) {
      flight.current = null;
      controls?.update();
    }
  });

  return (
    <OrbitControls
      makeDefault
      enablePan={false}
      enableDamping
      dampingFactor={0.08}
      rotateSpeed={0.6}
      minZoom={base * 0.6}
      maxZoom={base * 3}
      autoRotate={!reduced && !focus && !interacted}
      autoRotateSpeed={0.5}
      onStart={() => setInteracted(true)}
    />
  );
}
