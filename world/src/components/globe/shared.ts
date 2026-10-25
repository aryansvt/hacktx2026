import { CanvasTexture, Vector3 } from "three";
import { CASTLE, GLOBE_R, toXYZ } from "./geo";

// mutable scene state shared between globe parts, never react state
export const castlePos = new Vector3(...toXYZ(CASTLE.lat, CASTLE.lon, GLOBE_R));
export const castleUp = castlePos.clone().normalize();

export const live = {
  // current world position of each creature, written by creatures every frame
  positions: new Map<string, Vector3>(),
  // visibility (front side of the globe) per creature
  visible: new Map<string, boolean>(),
  // castle thump, decays to 0
  pulse: 0,
  // gate flash, decays to 0
  flash: 0,
};

export const palette = {
  midnight: "#0b1330",
  midnight2: "#14204a",
  gold: "#d4a52b",
  goldLight: "#f0cf6a",
  goldDeep: "#a87c14",
  parchment: "#efe3c8",
  red: "#c8412b",
  purple: "#a874ff",
};

const cache = new Map<string, CanvasTexture>();

// soft radial glow, used for creature dots, sparks and heat
export function glowTexture(): CanvasTexture {
  const hit = cache.get("glow");
  if (hit) return hit;
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d")!;
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.25, "rgba(255,255,255,0.7)");
  grad.addColorStop(0.6, "rgba(255,255,255,0.15)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  const t = new CanvasTexture(c);
  cache.set("glow", t);
  return t;
}

// crisp round dot for land points and crumbs
export function dotTexture(): CanvasTexture {
  const hit = cache.get("dot");
  if (hit) return hit;
  const c = document.createElement("canvas");
  c.width = c.height = 32;
  const g = c.getContext("2d")!;
  const grad = g.createRadialGradient(16, 16, 0, 16, 16, 16);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.55, "rgba(255,255,255,0.9)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.beginPath();
  g.arc(16, 16, 16, 0, Math.PI * 2);
  g.fill();
  const t = new CanvasTexture(c);
  cache.set("dot", t);
  return t;
}

// a little rune drawn on a canvas, for command glyphs over the castle
export const runes = ["ᚠ", "ᚱ", "ᚦ", "ᛟ", "ᚹ", "ᛉ", "✦", "§"];
export function runeTexture(ch: string): CanvasTexture {
  const id = `rune:${ch}`;
  const hit = cache.get(id);
  if (hit) return hit;
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d")!;
  g.shadowColor = "rgba(240,207,106,0.9)";
  g.shadowBlur = 12;
  g.fillStyle = "#f0cf6a";
  g.font = "bold 40px 'Segoe UI Symbol', 'Noto Sans Runic', serif";
  g.textAlign = "center";
  g.textBaseline = "middle";
  g.fillText(ch, 32, 34);
  const t = new CanvasTexture(c);
  cache.set(id, t);
  return t;
}
