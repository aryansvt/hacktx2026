import type { AttackerProfile, Kind, Source, Threat } from "./contracts";

export type Variant =
  | "golem" // bot, clay
  | "mage" // human
  | "fae" // agent
  | "shadow" // unknown
  | "slime" // harmless, any kind
  | "stone-golem" // malicious bot
  | "witch" // malicious human
  | "cursed-fae" // malicious agent
  | "dragon"; // max_threat critical

export interface Creature {
  variant: Variant;
  name: string; // "Clay golem"
  kind: string; // "bot", "human", "AI agent", "unclassified"
  label: string; // "Clay golem (bot)"
  color: string;
  malicious: boolean;
  scale: number; // 1 to 1.6 by visits
}

export const kindColor: Record<Kind, string> = {
  bot: "#4f8a3c",
  human: "#2f6fd6",
  agent: "#8e5bd0",
  unknown: "#7d7f88",
};

export const kindLabel: Record<Kind, string> = {
  bot: "bot",
  human: "human",
  agent: "AI agent",
  unknown: "unclassified",
};

const names: Record<Variant, string> = {
  golem: "Clay golem",
  mage: "Dark mage",
  fae: "Fae",
  shadow: "Shadow",
  slime: "Slime",
  "stone-golem": "Stone golem",
  witch: "Evil witch",
  "cursed-fae": "Cursed fae",
  dragon: "Dragon",
};

export function variantOf(a: AttackerProfile, max: Threat = a.threat): Variant {
  if (max === "critical") return "dragon";
  if (a.reputation === "harmless") return "slime";
  const evil = a.reputation === "malicious";
  switch (a.kind) {
    case "bot":
      return evil ? "stone-golem" : "golem";
    case "human":
      return evil ? "witch" : "mage";
    case "agent":
      return evil ? "cursed-fae" : "fae";
    default:
      return "shadow";
  }
}

export function creatureOf(
  a: AttackerProfile,
  max: Threat = a.threat,
  visits = 1,
): Creature {
  const variant = variantOf(a, max);
  const kind = kindLabel[a.kind];
  return {
    variant,
    name: names[variant],
    kind,
    label: `${names[variant]} (${kind})`,
    color: variant === "dragon" ? "#c8412b" : kindColor[a.kind],
    malicious: a.reputation === "malicious",
    scale: Math.min(1.6, 1 + Math.max(0, visits - 1) * 0.06),
  };
}

// team traffic is our own simulator; guests are judges at our table
export const sourceTag = (s: Source) =>
  s === "team"
    ? "simulated"
    : s === "guest"
      ? "guest"
      : s === "mock"
        ? "mock"
        : null;

export const threatLabel: Record<Threat, string> = {
  low: "Low",
  med: "Medium",
  high: "High",
  critical: "Critical",
};
