import { useEffect, useState } from "react";

export type DataMode = "live" | "mock";
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
  const [data, setData] = useState<MockData>("demo");
  // toggle shows in dev, and in prod only after pressing m
  const [toggle, setToggle] = useState(process.env.NODE_ENV !== "production");
  useEffect(() => {
    // read after mount so server and client markup match
    const d = devData();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setData(d ?? "demo");
    setMode(d ? "mock" : (stored() ?? fallback));
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
  return { mode, data, choose, toggle };
}
