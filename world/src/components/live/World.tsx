"use client";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Line, OrbitControls } from "@react-three/drei";
import {
  Component,
  useEffect,
  useMemo,
  useRef,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { Vector3, Quaternion, type Mesh, type OrthographicCamera } from "three";
import { useReducedMotion } from "framer-motion";
import { Bot, Flame, Ghost, Sparkles, User } from "lucide-react";
import { useDomain } from "@/lib/store";
import { useView } from "@/lib/view-store";
import { appearance } from "@/lib/domain";
import type { Geo } from "@/lib/contracts";
import points from "@/data/land-points.json";
import styles from "./live.module.css";
const vector = (g: Geo, r = 2.06) => {
  const lat = (g.lat * Math.PI) / 180,
    lon = (g.lon * Math.PI) / 180;
  return new Vector3(
    Math.cos(lat) * Math.sin(lon) * r,
    Math.sin(lat) * r,
    Math.cos(lat) * Math.cos(lon) * r,
  );
};
const fortress = vector({
  lat: 32.78,
  lon: -96.8,
  city: "Dallas",
  country: "US",
});
function Scene({
  onProjection,
  onMarker,
}: {
  onProjection: (x: number, y: number) => void;
  onMarker: (key: string, x: number, y: number, visible: boolean) => void;
}) {
  const data = useDomain((s) => s.data),
    view = useView();
  const reduced = useReducedMotion();
  const { camera, size } = useThree();
  const sphere = useRef<Mesh>(null!);
  const previous = useRef<Vector3 | null>(null);
  const [interacted, setInteracted] = useState(false);
  const selected =
    view.surface === "creature"
      ? data.attackers[view.selectedAttacker ?? ""]
      : null;
  const selectedPoint = selected ? vector(selected.geo) : null;
  const positions = useMemo(() => new Float32Array(points), []);
  // three.js camera is an imperative scene object, not react state.
  useEffect(() => {
    const cam = camera as OrthographicCamera;
    // eslint-disable-next-line react-hooks/immutability
    cam.zoom = (Math.min(size.width, size.height) / 900) * 175;
    cam.updateProjectionMatrix();
  }, [camera, size]);
  useEffect(() => {
    if (selected) {
      if (!previous.current) previous.current = camera.position.clone();
      camera.position.copy(vector(selected.geo, 7));
      camera.lookAt(0, 0, 0);
    } else if (previous.current) {
      camera.position.copy(previous.current);
      camera.lookAt(0, 0, 0);
      previous.current = null;
    }
  }, [camera, selected?.ip_hash]); // eslint-disable-line react-hooks/exhaustive-deps
  useFrame(() => {
    for (const a of Object.values(data.attackers)) {
      const p = vector(a.geo, 2.13);
      const visible = p.dot(camera.position.clone().sub(p)) > 0;
      const projected = p.clone().project(camera);
      onMarker(
        a.ip_hash,
        ((projected.x + 1) * size.width) / 2,
        ((1 - projected.y) * size.height) / 2,
        visible,
      );
    }
    if (selectedPoint) {
      const p = selectedPoint.clone().project(camera);
      onProjection(((p.x + 1) * size.width) / 2, ((1 - p.y) * size.height) / 2);
    }
  });
  return (
    <>
      <ambientLight intensity={1.6} />
      <directionalLight position={[4, 5, 6]} intensity={2} />
      <mesh ref={sphere}>
        <sphereGeometry args={[2, 64, 64]} />
        <meshStandardMaterial
          color="#d3dfed"
          roughness={0.85}
          metalness={0.08}
        />
      </mesh>
      <mesh>
        <sphereGeometry args={[2.035, 64, 64]} />
        <meshBasicMaterial
          color="#287dd0"
          transparent
          opacity={0.065}
          depthWrite={false}
        />
      </mesh>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[positions, 3]} />
        </bufferGeometry>
        <pointsMaterial color="#243c53" size={0.018} sizeAttenuation />
      </points>
      <group
        position={fortress}
        quaternion={new Quaternion().setFromUnitVectors(
          new Vector3(0, 1, 0),
          fortress.clone().normalize(),
        )}
      >
        <mesh position={[0, 0.07, 0]}>
          <boxGeometry args={[0.16, 0.14, 0.13]} />
          <meshStandardMaterial color="#d4a52b" />
        </mesh>
        {[-1, 1].flatMap((x) =>
          [-1, 1].map((z) => (
            <mesh key={`${x}${z}`} position={[x * 0.09, 0.12, z * 0.08]}>
              <boxGeometry args={[0.055, 0.24, 0.055]} />
              <meshStandardMaterial color="#d4a52b" />
            </mesh>
          )),
        )}
        <mesh rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[0.19, 0.21, 40]} />
          <meshBasicMaterial color="#d4a52b" side={2} />
        </mesh>
      </group>
      {Object.values(data.attackers).map((a) => {
        const p = vector(a.geo);
        const app = appearance(a.attacker, a.max_threat);
        const selected =
          a.ip_hash === view.selectedAttacker && view.surface === "creature";
        const dot = p.clone().normalize().dot(fortress.clone().normalize());
        const angle = Math.acos(Math.max(-1, Math.min(1, dot)));
        const arc = Array.from({ length: 49 }, (_, i) => {
          const t = i / 48;
          return p
            .clone()
            .multiplyScalar(Math.sin((1 - t) * angle))
            .add(fortress.clone().multiplyScalar(Math.sin(t * angle)))
            .divideScalar(Math.sin(angle) || 1)
            .normalize()
            .multiplyScalar(2.05 + Math.sin(t * Math.PI) * 0.32);
        });
        return (
          <group key={a.ip_hash}>
            <Line
              points={arc}
              color={app.color}
              lineWidth={selected ? 2 : 1}
              transparent
              opacity={selected ? 0.9 : 0.4}
            />
            <mesh
              position={p}
              onClick={(e) => {
                e.stopPropagation();
                view.select(a.ip_hash, a.latest_session_id, "map");
              }}
            >
              <octahedronGeometry args={[selected ? 0.075 : 0.05]} />
              <meshStandardMaterial color={app.color} />
            </mesh>
          </group>
        );
      })}
      <OrbitControls
        makeDefault
        enablePan={false}
        enableDamping
        dampingFactor={0.08}
        minZoom={80}
        maxZoom={320}
        autoRotate={!reduced && !selected && !interacted}
        autoRotateSpeed={2 / 3}
        onStart={() => {
          setInteracted(true);
        }}
      />
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
        The 3D globe could not load. You can still inspect every encounter in
        Live Feed. Reload to try WebGL again.
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
  const data = useDomain((s) => s.data),
    view = useView();
  const markers = useRef<Record<string, HTMLButtonElement | null>>({});
  const onMarker = useCallback(
    (key: string, x: number, y: number, visible: boolean) => {
      const el = markers.current[key];
      if (el) {
        el.style.transform = `translate(${x - 15}px,${y - 15}px)`;
        el.style.visibility = visible ? "visible" : "hidden";
      }
    },
    [],
  );
  return (
    <Boundary>
      <Canvas
        orthographic
        camera={{ position: [-2, 2, 6], zoom: 175, near: 0.1, far: 100 }}
        dpr={[1, 1.5]}
        fallback={
          <p className={styles.error}>
            WebGL is unavailable. Use Live Feed to inspect encounters.
          </p>
        }
      >
        <Scene onProjection={onProjection} onMarker={onMarker} />
      </Canvas>
      <div style={{ position: "absolute", inset: 0, pointerEvents: "none" }}>
        {Object.values(data.attackers).map((a) => {
          const app = appearance(a.attacker, a.max_threat);
          const Icon =
            app.variant === "dragon"
              ? Flame
              : a.attacker.kind === "unknown"
                ? Ghost
                : a.attacker.kind === "bot"
                  ? Bot
                  : a.attacker.kind === "human"
                    ? User
                    : Sparkles;
          return (
            <button
              key={a.ip_hash}
              ref={(el) => {
                markers.current[a.ip_hash] = el;
              }}
              className={`${styles.marker} ${view.surface === "creature" && view.selectedAttacker === a.ip_hash ? styles.selectedMarker : ""}`}
              style={{
                position: "absolute",
                left: 0,
                top: 0,
                pointerEvents: "auto",
                color: app.color,
                visibility: "hidden",
                zIndex: view.selectedAttacker === a.ip_hash ? 4 : 1,
              }}
              aria-label={`Inspect ${app.name} from ${a.geo.city}`}
              onClick={() => view.select(a.ip_hash, a.latest_session_id, "map")}
            >
              <Icon />
            </button>
          );
        })}
      </div>
    </Boundary>
  );
}
