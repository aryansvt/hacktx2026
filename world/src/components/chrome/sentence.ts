import type {
  AttackEvent,
  AttackerSummary,
  SessionSummary,
} from "../../lib/contracts";
import { creatureOf } from "../../lib/creatures";
import { placeOf } from "./place";

const clip = (s: string, n = 48) =>
  s.length > n ? `${s.slice(0, n - 1).trimEnd()}…` : s;
const plural = (n: number, one: string, many = `${one}s`) =>
  `${n} ${n === 1 ? one : many}`;
const article = (s: string) => (/^[aeiou]/i.test(s) ? `an ${s}` : `a ${s}`);

// commands are wrapped in backticks so the ui can render them as code
export function sentence(e: AttackEvent, a?: AttackerSummary): string {
  const c = a
    ? creatureOf(a.attacker, a.max_threat, a.visits, a.source)
    : creatureOf(e.attacker, e.attacker.threat, 1, e.source);
  const who = `${c.label} from ${placeOf(e.geo)}`;
  switch (e.type) {
    case "session_start":
      return e.detail.guest_name
        ? `${who} approached the gate as ${clip(e.detail.guest_name, 32)}`
        : `${who} approached the gate`;
    case "login_fail":
      return `${who} tried to log in as \`${clip(e.detail.username, 32)}\``;
    case "login_success":
      return `${who} logged in`;
    case "command":
      return `${who} ran \`${clip(e.detail.command.replace(/\s+/g, " ").trim())}\``;
    case "tripwire":
      return `${who} fell for a tripwire`;
    case "classified":
      return `${who} was classified as ${article(c.kind)}`;
    case "dossier":
      return `${who} got a web reputation check: ${e.attacker.reputation}`;
    case "story":
      return `The scribe wrote down the story of ${who}`;
    case "session_end":
      return e.detail.command_count > 0
        ? `${who} left after ${plural(e.detail.command_count, "command")}`
        : `${who} left without running anything`;
  }
}

// fallback rows before any live events arrive
export function sessionSentence(
  s: SessionSummary,
  a?: AttackerSummary,
): string {
  const c = a
    ? creatureOf(a.attacker, a.max_threat, a.visits, a.source)
    : creatureOf(s.attacker, s.attacker.threat, 1, s.source);
  const who = `${c.label} from ${placeOf(s.geo)}`;
  const ran = plural(s.command_count, "command");
  switch (s.status) {
    case "approaching":
      return `${who} is approaching the gate`;
    case "at_gate":
      return s.login_fails > 0
        ? `${who} is at the gate after ${plural(s.login_fails, "failed login")}`
        : `${who} is at the gate`;
    case "inside":
      return `${who} is inside and has run ${ran}`;
    case "ended":
      if (s.command_count > 0) return `${who} ran ${ran} and left`;
      if (s.login_fails > 0)
        return `${who} knocked ${plural(s.login_fails, "time")} and left`;
      return `${who} came by and left`;
  }
}

// splits on backticks: odd parts are code
export const parts = (s: string) => s.split("`");
