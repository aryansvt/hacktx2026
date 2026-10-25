"use client";
import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import {
  AdditiveBlending,
  BackSide,
  BufferGeometry,
  Color,
  Float32BufferAttribute,
  ShaderMaterial,
} from "three";
import points from "@/data/land-points.json";
import { dotTexture, palette } from "./shared";
import { GLOBE_R, hash01, toXYZ } from "./geo";

// two golds, picked per point so continents shimmer a little
const land = (() => {
  const pos = new Float32Array(points as number[]);
  const col = new Float32Array(pos.length);
  const a = new Color(palette.gold),
    b = new Color(palette.goldLight);
  const tmp = new Color();
  for (let i = 0; i < pos.length / 3; i++) {
    tmp.copy(a).lerp(b, hash01(String(i), 7));
    col[i * 3] = tmp.r;
    col[i * 3 + 1] = tmp.g;
    col[i * 3 + 2] = tmp.b;
  }
  return { pos, col };
})();

// faint lat/lon lines, like a planetarium globe
const graticule = (() => {
  const v: number[] = [];
  const r = GLOBE_R + 0.004;
  for (let lat = -60; lat <= 60; lat += 30)
    for (let lon = -180; lon < 180; lon += 4) {
      v.push(...toXYZ(lat, lon, r), ...toXYZ(lat, lon + 4, r));
    }
  for (let lon = -180; lon < 180; lon += 30)
    for (let lat = -84; lat < 84; lat += 4) {
      v.push(...toXYZ(lat, lon, r), ...toXYZ(lat + 4, lon, r));
    }
  const g = new BufferGeometry();
  g.setAttribute("position", new Float32BufferAttribute(v, 3));
  return g;
})();

// stars live in a shell well outside the globe; the near side falls behind the camera
const starGeo = (() => {
  const n = 9000;
  const pos = new Float32Array(n * 3),
    seed = new Float32Array(n),
    size = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    const u = hash01(String(i), 11) * 2 - 1,
      t = hash01(String(i), 12) * Math.PI * 2;
    const r = 11 + hash01(String(i), 13) * 8;
    const s = Math.sqrt(1 - u * u);
    pos[i * 3] = s * Math.cos(t) * r;
    pos[i * 3 + 1] = u * r;
    pos[i * 3 + 2] = s * Math.sin(t) * r;
    seed[i] = hash01(String(i), 14) * 100;
    size[i] = 1 + Math.pow(hash01(String(i), 15), 4) * 3.2;
  }
  const g = new BufferGeometry();
  g.setAttribute("position", new Float32BufferAttribute(pos, 3));
  g.setAttribute("seed", new Float32BufferAttribute(seed, 1));
  g.setAttribute("size", new Float32BufferAttribute(size, 1));
  return g;
})();

export function Earth({ reduced }: { reduced: boolean }) {
  const stars = useRef<ShaderMaterial>(null!);
  const atmosphere = useMemo(
    () =>
      new ShaderMaterial({
        uniforms: {
          inner: { value: new Color("#4d6fd8") },
          outer: { value: new Color(palette.goldLight) },
        },
        vertexShader: `
          varying vec3 vN;
          void main() {
            vN = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }`,
        fragmentShader: `
          uniform vec3 inner; uniform vec3 outer;
          varying vec3 vN;
          void main() {
            // brightest at the globe's edge, fading out to the halo's edge
            float z = abs(vN.z);
            float glow = pow(z, 2.2);
            vec3 c = mix(outer, inner, smoothstep(0.2, 0.6, z));
            gl_FragColor = vec4(c, glow * 0.75);
          }`,
        side: BackSide,
        blending: AdditiveBlending,
        transparent: true,
        depthWrite: false,
      }),
    [],
  );
  const rim = useMemo(
    () =>
      new ShaderMaterial({
        uniforms: { tint: { value: new Color("#5b7be6") } },
        vertexShader: `
          varying vec3 vN;
          void main() {
            vN = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }`,
        fragmentShader: `
          uniform vec3 tint; varying vec3 vN;
          void main() {
            float f = pow(1.0 - max(vN.z, 0.0), 3.0);
            gl_FragColor = vec4(tint, f * 0.6);
          }`,
        blending: AdditiveBlending,
        transparent: true,
        depthWrite: false,
      }),
    [],
  );
  const starMat = useMemo(
    () =>
      new ShaderMaterial({
        uniforms: { time: { value: 0 } },
        vertexShader: `
          attribute float seed; attribute float size;
          uniform float time;
          varying float vA;
          void main() {
            vA = 0.55 + 0.45 * sin(time * (0.6 + fract(seed) * 1.6) + seed);
            gl_PointSize = size;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }`,
        fragmentShader: `
          varying float vA;
          void main() {
            vec2 p = gl_PointCoord - 0.5;
            float d = length(p);
            if (d > 0.5) discard;
            gl_FragColor = vec4(vec3(1.0, 0.95, 0.82), vA * (1.0 - d * 1.6));
          }`,
        transparent: true,
        depthWrite: false,
      }),
    [],
  );
  useFrame((_, dt) => {
    if (!reduced && stars.current) stars.current.uniforms.time.value += dt;
  });
  return (
    <>
      <ambientLight intensity={0.55} color="#b9c6ff" />
      <directionalLight position={[4, 5, 6]} intensity={1.6} color="#fff1d0" />
      <directionalLight position={[-6, -2, -4]} intensity={0.4} color="#5b7be6" />
      <points geometry={starGeo}>
        <primitive object={starMat} ref={stars} attach="material" />
      </points>
      {/* atmosphere halo behind the globe */}
      <mesh scale={1.16}>
        <sphereGeometry args={[GLOBE_R, 64, 64]} />
        <primitive object={atmosphere} attach="material" />
      </mesh>
      <mesh>
        <sphereGeometry args={[GLOBE_R, 96, 96]} />
        <meshStandardMaterial
          color={palette.midnight2}
          emissive={palette.midnight}
          emissiveIntensity={0.6}
          roughness={0.9}
          metalness={0.1}
        />
      </mesh>
      <mesh scale={1.002}>
        <sphereGeometry args={[GLOBE_R, 64, 64]} />
        <primitive object={rim} attach="material" />
      </mesh>
      <lineSegments geometry={graticule}>
        <lineBasicMaterial
          color={palette.gold}
          transparent
          opacity={0.08}
          depthWrite={false}
        />
      </lineSegments>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[land.pos, 3]} />
          <bufferAttribute attach="attributes-color" args={[land.col, 3]} />
        </bufferGeometry>
        <pointsMaterial
          vertexColors
          size={0.026}
          sizeAttenuation
          map={dotTexture()}
          alphaTest={0.3}
          transparent
        />
      </points>
    </>
  );
}
