/**
 * IP handling (spec section 8, R10). Addresses are stored ONLY as prefixes: IPv4 /24 and IPv6 /48.
 * `::ffff:a.b.c.d` (IPv4-mapped IPv6, what Node reports on dual-stack sockets) is unmapped to IPv4 first.
 */
import { isIPv4, isIPv6 } from 'node:net';

/** Normalise an address: trim, strip [brackets] and %zone, unmap ::ffff:a.b.c.d. Returns null if invalid. */
export function normalizeIp(ip: string | null | undefined): string | null {
  if (!ip) return null;
  let s = ip.trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (mapped?.[1]) s = mapped[1];
  return isIPv4(s) || isIPv6(s) ? s : null;
}

/** Expand an IPv6 address (validated by isIPv6) to 8 numeric hextets. */
function expandIPv6(addr: string): number[] {
  let s = addr.toLowerCase();
  const dotted = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number) as [number, number, number, number];
    s = `${s.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = '', tail] = s.split('::');
  const left = head ? head.split(':') : [];
  const right = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const fill = tail === undefined ? [] : Array<string>(8 - left.length - right.length).fill('0');
  return [...left, ...fill, ...right].map((h) => parseInt(h, 16));
}

/** RFC 5952 canonical text of 8 hextets (longest run of 2+ zero hextets becomes "::"). */
function compressIPv6(hextets: number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (hextets[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && hextets[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = hextets.map((h) => h.toString(16));
  if (bestLen < 2) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

/** IPv4 -> "a.b.c.0/24"; IPv6 -> "<first 48 bits>::/48". Null when missing or invalid. */
export function ipPrefix(ip: string | null | undefined): string | null {
  const s = normalizeIp(ip);
  if (!s) return null;
  if (isIPv4(s)) {
    const [a, b, c] = s.split('.').map(Number);
    return `${a}.${b}.${c}.0/24`;
  }
  const h = expandIPv6(s);
  return `${compressIPv6([h[0] ?? 0, h[1] ?? 0, h[2] ?? 0, 0, 0, 0, 0, 0])}/48`;
}

/**
 * Rate-limit key for "per IP" limits: the full IPv4 address, or the IPv6 /64 (one subscriber's allocation,
 * so rotating addresses inside it does not reset the counter). "unknown" when the address is missing.
 */
export function ipKey(ip: string | null | undefined): string {
  const s = normalizeIp(ip);
  if (!s) return 'unknown';
  if (isIPv4(s)) return s;
  const h = expandIPv6(s);
  return `${compressIPv6([h[0] ?? 0, h[1] ?? 0, h[2] ?? 0, h[3] ?? 0, 0, 0, 0, 0])}/64`;
}

/**
 * Key for per-client shares of the in-flight chunk slots (C-R3-03): the full IPv4 address, or the IPv6 /48.
 * A subscriber is commonly delegated a /56 or a /48 (free from tunnel brokers), so keying on the /64 would
 * give one client 256 or 65,536 shares. "unknown" when the address is missing.
 */
export function ipShareKey(ip: string | null | undefined): string {
  const s = normalizeIp(ip);
  if (!s) return 'unknown';
  if (isIPv4(s)) return s;
  return ipPrefix(s) ?? 'unknown';
}
