"use client";
import type { MockData } from "@/lib/data-mode";

// dev-only break-ui switch: swaps the mock fixture through ?data=
const options: [MockData, string][] = [
  ["demo", "Demo data"],
  ["worst", "Worst case"],
  ["empty", "Empty"],
];

export default function DevDataToggle({ current }: { current: MockData }) {
  return (
    <>
      {/* narrow screens: keep it clear of the latest card */}
      <style>{`@media (max-width: 760px) { .dev-data-toggle { bottom: auto !important; top: 50% !important; } }`}</style>
      <div
        className="dev-data-toggle"
        role="radiogroup"
        aria-label="Fixture data (dev only)"
        style={{
          position: "fixed",
          bottom: 84,
          left: "50%",
          transform: "translateX(-50%)",
          zIndex: 90,
          display: "flex",
          gap: 2,
          padding: 3,
          borderRadius: 999,
          background: "#d4d4d8",
          font: "12px system-ui, sans-serif",
        }}
      >
        {options.map(([value, label]) => (
          <a
            key={value}
            role="radio"
            aria-checked={current === value}
            href={`?data=${value}`}
            style={{
              padding: "4px 12px",
              borderRadius: 999,
              color: "#111",
              textDecoration: "none",
              background: current === value ? "#fff" : "transparent",
            }}
          >
            {label}
          </a>
        ))}
      </div>
    </>
  );
}
