import { useEffect, useState } from "react";
import { create } from "zustand";

export type DataMode = "live" | "mock" | "replay";
export type MockData = "demo" | "worst" | "empty";

// dev only: ?data=worst or ?data=empty swaps the mock fixture (break-ui)
export function devData(): MockData | null {
  if (process.env.NODE_ENV === "production") return null;
  try {
    const v = new URLSearchParams(window.location.search).get("data");
    return v === "worst" || v === "empty" || v === "demo" ? v : null;
  } catch {
    return null;
  }
}
const KEY = "breadcrumbs:data-mode";
const modes: DataMode[] = ["live", "mock", "replay"];
const isMode = (v: string | null | undefined): v is DataMode =>
  modes.includes(v as DataMode);

// NEXT_PUBLIC_MODE wins; the older NEXT_PUBLIC_MOCK=1 still means mock.
// with neither, replay: the live backend is gone
export const envMode = (mode?: string, mock?: string): DataMode =>
  isMode(mode) ? mode : mock === "1" ? "mock" : "replay";

// live needs a backend, so it's only offered when the build points at one
export const allowedModes = (env: DataMode): DataMode[] =>
  env === "live" ? ["live", "replay", "mock"] : ["replay", "mock"];

export const pickMode = (stored: string | null, env: DataMode): DataMode =>
  isMode(stored) && allowedModes(env).includes(stored) ? stored : env;

// the mode in use, for copy that changes with it
export const useMode = create<{ mode: DataMode | null }>(() => ({
  mode: null,
}));

function stored(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function useDataMode() {
  const env = envMode(
    process.env.NEXT_PUBLIC_MODE,
    process.env.NEXT_PUBLIC_MOCK,
  );
  const [mode, setMode] = useState<DataMode | null>(null);
  const [data, setData] = useState<MockData>("demo");
  // toggle shows in dev, and in prod only after pressing m
  const [toggle, setToggle] = useState(process.env.NODE_ENV !== "production");
  useEffect(() => {
    // read after mount so server and client markup match
    const d = devData();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setData(d ?? "demo");
    setMode(d ? "mock" : pickMode(stored(), env));
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.closest("input, textarea, select, [contenteditable]")) return;
      if (e.key === "m" || e.key === "M") setToggle((v) => !v);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [env]);
  useEffect(() => {
    useMode.setState({ mode });
  }, [mode]);
  const choose = (m: DataMode) => {
    try {
      localStorage.setItem(KEY, m);
    } catch {}
    setMode(m);
  };
  return { mode, data, choose, toggle, options: allowedModes(env) };
}
