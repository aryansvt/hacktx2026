// text scrubbing for the public replay snapshot: secrets out, ips swapped
// for documentation addresses (the same ip always gets the same stand-in)

export type IpMap = Map<string, string>;
export const newIpMap = (): IpMap => new Map();

const R = "[redacted]";
// documentation ranges (rfc 5737), used in order
const v4Pools = ["203.0.113", "198.51.100", "192.0.2"];

// private, loopback and documentation addresses identify nobody
function keepV4(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  return (
    a === 127 ||
    a === 0 ||
    a === 10 ||
    a >= 224 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    v4Pools.some((p) => ip.startsWith(p + "."))
  );
}

function standIn(ips: IpMap, ip: string, v6: boolean): string {
  const key = ip.toLowerCase();
  const hit = ips.get(key);
  if (hit) return hit;
  const i = [...ips.keys()].filter((k) => k.includes(":") === v6).length;
  const out = v6
    ? `2001:db8::${(i + 1).toString(16)}`
    : `${v4Pools[Math.floor(i / 254) % v4Pools.length]}.${(i % 254) + 1}`;
  ips.set(key, out);
  return out;
}

// key names in KEY=value or key: value pairs that hold secrets
const secretKey =
  /pass|pwd|secret|token|api.?key|access.?key|private.?key|(^|_)key$|auth|credential|salt/i;

const rules: [RegExp, string | ((...m: string[]) => string)][] = [
  // pem blocks, even when the end marker was cut off
  [
    /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?(?:-----END \1-----|$)/g,
    "[redacted key]",
  ],
  [
    /\b(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]{16,}/g,
    "$1 [redacted key]",
  ],
  [/\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*/g, "[redacted token]"],
  [
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_\w{20,}|\bxox[abprs]-[\w-]{10,}|\bsk-[\w-]{20,}|\b[rs]k_(?:live|test)_\w{8,}|\bAIza[\w-]{30,}|\bglpat-[\w-]{20,}/g,
    "[redacted token]",
  ],
  // scheme://user:password@host
  [/\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+):([^\s@/'"]+)@/gi, `$1:${R}@`],
  [
    /\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token)(\s*[:=]\s*)((?:bearer|basic|token|digest)\s+)?[^\s'"]+/gi,
    `$1$2$3${R}`,
  ],
  [/\b(bearer)\s+[\w.~+/=-]{6,}/gi, `$1 ${R}`],
  [
    /([?&][^=&\s#'"]*(?:key|token|auth|sig|secret|pass)[^=&\s#'"]*=)[^&\s#'"]+/gi,
    `$1${R}`,
  ],
  // echo "user:pass" | chpasswd
  [/([^\s'":|]+):([^\s'"|]+)(['"]?\s*\|\s*(?:sudo\s+)?chpasswd)/g, `$1:${R}$3`],
  // echo -e "pass\npass" | passwd
  [
    /(echo\s+(?:-\w+\s+)?)(["']?)[^|]*?\2(\s*\|\s*(?:sudo\s+)?passwd\b)/g,
    `$1$2${R}$2$3`,
  ],
  [/\b(sshpass\s+-p)\s*\S+/g, `$1 ${R}`],
  [/\b(mysql(?:dump|admin)?\b[^;|&\n]*?\s-p)\S+/g, `$1${R}`],
  [/\b((?:usermod|useradd)\b[^;|&\n]*?\s-p\s+)\S+/g, `$1${R}`],
  // crypt hashes ($1$, $5$, $6$, $y$, bcrypt)
  [/\$(?:1|2[abxy]?|5|6|y|gy|7)\$[^\s:'"]{8,}/g, "[redacted hash]"],
  [
    /(?<![/\w.-])([\w.-]+)(["']?\s*[=:]\s*)(["']?)([^\s"'&;,]+)\3/g,
    (all, key, sep, q, value) =>
      secretKey.test(key) &&
      !value.startsWith("[redacted") &&
      !/^\$\w/.test(value)
        ? `${key}${sep}${q}${R}${q}`
        : all,
  ],
  [/\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b/g, "user@example.com"],
];

export function scrubText(s: string, ips: IpMap): string {
  let out = s;
  for (const [re, to] of rules)
    out = out.replace(
      re,
      to as (substring: string, ...args: string[]) => string,
    );
  // ipv4, but not pieces of version strings like 1.34.0.1.22
  out = out.replace(
    /(?<![\w.-])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w-]|\.\d)/g,
    (ip) => (keepV4(ip) ? ip : standIn(ips, ip, false)),
  );
  // partial prefixes from ip lookup sites: 45.9.17.*, 45.9.x.x
  out = out.replace(
    /(?<![\w.])(?:(?:\d{1,3}|\*|x)\.){2,3}(?:\d{1,3}|\*|x)(?!\w|\.(?:\d|\*|x\b))/gi,
    (m) => {
      const parts = m.split(".");
      const nums = parts.filter((p) => /^\d+$/.test(p));
      if (!nums.length || nums.length === parts.length) return m;
      if (nums.some((p) => +p > 255)) return m;
      return parts.map((p) => (/^\d+$/.test(p) ? "x" : p)).join(".");
    },
  );
  // a bare /24 in prose ("the 45.9.17 block"). versions start low, have
  // leading zeros, or sit after = or /, so they stay
  out = out.replace(
    /(?<![\w.=/-])(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w-]|\.\w)/g,
    (m, a: string, b: string, c: string) =>
      +a >= 32 && [a, b, c].every((p) => +p <= 255 && !/^0\d/.test(p))
        ? "x.x.x"
        : m,
  );
  // ipv6 with :: or at least four colons; times like 19:32:17 don't qualify
  out = out.replace(
    /(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])/gi,
    (ip) => {
      const colons = ip.split(":").length - 1;
      const v6 = ip.includes("::")
        ? colons >= 2 && /[0-9a-f]/i.test(ip)
        : colons >= 4;
      if (!v6 || /^(::1|fe80:|fc|fd)/i.test(ip) || ip.startsWith("2001:db8"))
        return ip;
      return standIn(ips, ip, true);
    },
  );
  return out;
}

// a url keeps its path only if nothing in it can point back at a visitor
export function scrubUrl(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  const path = decodeURIComponent(u.pathname);
  const identifying =
    // whole or partial ips, also split by slashes (/ip_info/EN/45/9.htm)
    /(?<!\d)\d{1,3}(?:[./_-]\d{1,3}){1,3}(?!\d)|\d{5,}|[0-9a-f]{16,}|[A-Za-z0-9+_]{32,}|:.*:/i.test(
      path,
    );
  return identifying ? `${u.origin}/` : `${u.origin}${u.pathname}`;
}
