import type { Geo } from "../../lib/contracts";

// country name from an iso2 code, null when unknown
export function countryName(code: string): string | null {
  if (!code || code === "XX") return null;
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

// city if we have one, else the country, else a vague fallback
export const placeOf = (geo: Geo) =>
  geo.city || countryName(geo.country) || "parts unknown";

// regional indicator flag emoji, empty for unknown
export function flagOf(code: string): string {
  if (!/^[A-Za-z]{2}$/.test(code) || code.toUpperCase() === "XX") return "";
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65),
  );
}

export function ago(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (!Number.isFinite(s)) return "";
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
