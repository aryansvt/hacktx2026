import { useEffect, useState } from "react";

export type DataMode = "live" | "mock";
const KEY = "breadcrumbs:data-mode";

// mock only when the env flag is exactly "1"
export const envMode = (value: string | undefined): DataMode =>
  value === "1" ? "mock" : "live";

function stored(): DataMode | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === "live" || v === "mock" ? v : null;
  } catch {
    return null;
  }
}

export function useDataMode() {
  const fallback = envMode(process.env.NEXT_PUBLIC_MOCK);
  const [mode, setMode] = useState<DataMode | null>(null);
  // toggle shows in dev, and in prod only after pressing m
  const [toggle, setToggle] = useState(process.env.NODE_ENV !== "production");
  useEffect(() => {
    // read after mount so server and client markup match
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMode(stored() ?? fallback);
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.closest("input, textarea, select, [contenteditable]")) return;
      if (e.key === "m" || e.key === "M") setToggle((v) => !v);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [fallback]);
  const choose = (m: DataMode) => {
    try {
      localStorage.setItem(KEY, m);
    } catch {}
    setMode(m);
  };
  return { mode, choose, toggle };
}
