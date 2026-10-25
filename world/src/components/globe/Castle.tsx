"use client";
import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import {
  AdditiveBlending,
  DoubleSide,
  Quaternion,
  Vector3,
  type Group,
  type Mesh,
  type MeshBasicMaterial,
} from "three";
import { castlePos, castleUp, glowTexture, live, palette } from "./shared";
import { screen } from "@/lib/screen";

const stone = "#e9d9b2";
const roof = "#c8412b";
const roofBlue = "#1f3c88";

// corner towers then the keep, all in castle units (x, z, height, radius)
const towers: [number, number, number, number, string][] = [
  [-0.075, -0.06, 0.11, 0.022, roof],
  [0.075, -0.06, 0.11, 0.022, roofBlue],
  [-0.075, 0.06, 0.09, 0.02, roofBlue],
  [0.075, 0.06, 0.09, 0.02, roof],
  [0, -0.01, 0.16, 0.03, roof],
];

export function Castle({ reduced }: { reduced: boolean }) {
  const group = useRef<Group>(null!);
  const beam = useRef<Mesh>(null!);
  const ring = useRef<Mesh>(null!);
  const flash = useRef<Mesh>(null!);
  const banners = useRef<Group>(null!);
  const quat = useMemo(
    () => new Quaternion().setFromUnitVectors(new Vector3(0, 1, 0), castleUp),
    [],
  );
  const tmp = useMemo(() => new Vector3(), []);
  useFrame((state, dt) => {
    const t = state.clock.elapsedTime;
    live.pulse = Math.max(0, live.pulse - dt * 2.4);
    live.flash = Math.max(0, live.flash - dt * 1.6);
    const s = 1 + live.pulse * 0.22;
    group.current.scale.setScalar(s);
    const beamMat = beam.current.material as MeshBasicMaterial;
    beamMat.opacity =
      0.32 + (reduced ? 0 : Math.sin(t * 1.7) * 0.06) + live.flash * 0.5;
    const ringMat = ring.current.material as MeshBasicMaterial;
    ringMat.opacity = 0.55 + (reduced ? 0 : Math.sin(t * 2.2) * 0.15) + live.flash * 0.4;
    const fm = flash.current.material as MeshBasicMaterial;
    fm.opacity = live.flash * 0.9;
    flash.current.scale.setScalar(0.3 + live.flash * 0.5);
    if (!reduced)
      banners.current.children.forEach((b, i) => {
        b.rotation.y = Math.sin(t * 3 + i) * 0.35;
      });
    // screen anchor for the castle
    const cam = state.camera;
    tmp.copy(castlePos).project(cam);
    screen.castle.x = ((tmp.x + 1) * state.size.width) / 2;
    screen.castle.y = ((1 - tmp.y) * state.size.height) / 2;
    screen.castle.visible = castleUp.dot(cam.position) > 0;
  });
  return (
    <group position={castlePos} quaternion={quat}>
      {/* gate ring on the ground where creatures gather */}
      <mesh ref={ring} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.004, 0]}>
        <ringGeometry args={[0.15, 0.165, 64]} />
        <meshBasicMaterial
          color={palette.goldLight}
          transparent
          side={DoubleSide}
          blending={AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.003, 0]}>
        <circleGeometry args={[0.15, 48]} />
        <meshBasicMaterial
          color={palette.gold}
          transparent
          opacity={0.08}
          blending={AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
      {/* light beam into the sky */}
      <mesh ref={beam} position={[0, 0.55, 0]}>
        <cylinderGeometry args={[0.006, 0.03, 1.1, 16, 1, true]} />
        <meshBasicMaterial
          color={palette.goldLight}
          transparent
          blending={AdditiveBlending}
          depthWrite={false}
          side={DoubleSide}
        />
      </mesh>
      <sprite position={[0, 0.06, 0]} scale={[0.5, 0.5, 0.5]}>
        <spriteMaterial
          map={glowTexture()}
          color={palette.gold}
          transparent
          opacity={0.45}
          blending={AdditiveBlending}
          depthWrite={false}
        />
      </sprite>
      <mesh ref={flash} position={[0, 0.03, 0.09]}>
        <sphereGeometry args={[0.1, 16, 16]} />
        <meshBasicMaterial
          color="#fff3c4"
          transparent
          opacity={0}
          blending={AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
      <group ref={group}>
        {/* curtain walls */}
        <mesh position={[0, 0.025, 0]}>
          <boxGeometry args={[0.15, 0.05, 0.12]} />
          <meshStandardMaterial color={stone} emissive={palette.goldDeep} emissiveIntensity={0.35} />
        </mesh>
        {/* gate arch */}
        <mesh position={[0, 0.018, 0.061]}>
          <boxGeometry args={[0.03, 0.036, 0.004]} />
          <meshStandardMaterial color="#3a2a14" emissive={palette.gold} emissiveIntensity={0.9} />
        </mesh>
        {towers.map(([x, z, h, r, c], i) => (
          <group key={i} position={[x, 0, z]}>
            <mesh position={[0, h / 2, 0]}>
              <cylinderGeometry args={[r, r * 1.08, h, 12]} />
              <meshStandardMaterial color={stone} emissive={palette.goldDeep} emissiveIntensity={0.3} />
            </mesh>
            <mesh position={[0, h + r * 1.4, 0]}>
              <coneGeometry args={[r * 1.35, r * 2.8, 12]} />
              <meshStandardMaterial color={c} emissive={c} emissiveIntensity={0.35} />
            </mesh>
            {/* lit window */}
            <mesh position={[0, h * 0.65, r * 0.98]}>
              <boxGeometry args={[r * 0.5, r * 0.8, 0.002]} />
              <meshBasicMaterial color={palette.goldLight} />
            </mesh>
          </group>
        ))}
        <group ref={banners}>
          {towers.map(([x, z, h, r], i) => (
            <group key={i} position={[x, h + r * 2.8, z]}>
              <mesh position={[0, 0.012, 0]}>
                <cylinderGeometry args={[0.0015, 0.0015, 0.024, 4]} />
                <meshBasicMaterial color="#3a2a14" />
              </mesh>
              <mesh position={[0.009, 0.019, 0]}>
                <planeGeometry args={[0.018, 0.01]} />
                <meshBasicMaterial
                  color={i % 2 ? palette.gold : palette.red}
                  side={DoubleSide}
                />
              </mesh>
            </group>
          ))}
        </group>
      </group>
    </group>
  );
}
