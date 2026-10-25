import type { AttackEvent } from "@/lib/contracts";

// soft bell notes per event, pentatonic so overlaps never clash
export const chimeFor = (e: AttackEvent): number[] | null => {
  switch (e.type) {
    case "session_start":
      return e.source === "guest" ? [523.25, 659.25, 783.99] : null;
    case "login_success":
      return [392, 523.25];
    case "tripwire":
      return [659.25, 587.33, 783.99];
    case "dossier":
      return [523.25, 783.99, 1046.5];
    default:
      return null;
  }
};
