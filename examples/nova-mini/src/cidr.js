/**
 * Cloudflare IP ranges and candidate generation.
 *
 * Inspired by IRNova/NovaRadar (MIT), which is a desktop Go scanner. Its
 * approach is sound but it cannot run here: a Worker cannot open raw TCP to
 * an arbitrary IP (Cloudflare's SSRF sandbox blocks it), so real scanning has
 * to happen on your machine. What ports well is the range data and the
 * candidate-generation logic, which is what this module provides.
 *
 * Deliberately NOT copied from that project:
 *   - its hardcoded TLS SNI (nova2.altramax083.workers.dev), which would have
 *     verified IPs against the author's domain rather than yours
 *   - its hardcoded VLESS UUID
 *   - third-party list URLs (cmliu, Blacknuno), which the audit removed
 */

/**
 * Cloudflare's published IPv4 ranges, used as a fallback when the live list
 * cannot be fetched. Same set NovaRadar ships, and it matches
 * cloudflare.com/ips-v4.
 */
export const CLOUDFLARE_V4 = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];

/** Ports Cloudflare terminates TLS on. */
export const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

/** Plaintext HTTP ports, listed for completeness; TLS is what you want. */
export const HTTP_PORTS = [80, 2052, 2082, 2086, 2095, 8080];

const OFFICIAL_V4_URL = 'https://www.cloudflare.com/ips-v4';

let cache = null;
let cachedAt = 0;
const CACHE_MS = 24 * 60 * 60 * 1000;

/**
 * Fetch Cloudflare's official ranges, falling back to the built-in list.
 * This is the one network call here and it goes to Cloudflare itself, not to
 * any third party.
 */
export async function fetchCloudflareRanges(fetchImpl = fetch, { refresh = false } = {}) {
  const now = Date.now();
  if (!refresh && cache && now - cachedAt < CACHE_MS) return cache.slice();

  try {
    const response = await fetchImpl(OFFICIAL_V4_URL, {
      cf: { cacheTtl: 86400, cacheEverything: true },
    });
    if (response.ok) {
      const ranges = parseCidrList(await response.text());
      if (ranges.length) {
        cache = ranges;
        cachedAt = now;
        return ranges.slice();
      }
    }
  } catch {
    // fall through to the built-in list
  }

  cache = CLOUDFLARE_V4.slice();
  cachedAt = now;
  return cache.slice();
}

/** Keep only well-formed IPv4 CIDRs; drop comments and junk. */
export function parseCidrList(text) {
  return String(text || '')
    .split(/[\s,]+/)
    .map((line) => line.trim())
    .filter((line) => isValidCidr(line));
}

export function isValidCidr(value) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(String(value));
  if (!match) return false;
  const bits = Number(match[5]);
  if (bits < 0 || bits > 32) return false;
  return match.slice(1, 5).every((octet) => Number(octet) <= 255);
}

export function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => ((acc << 8) >>> 0) + Number(octet), 0) >>> 0;
}

export function intToIp(value) {
  const n = value >>> 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** [firstUsable, lastUsable] for a CIDR, skipping network and broadcast. */
export function cidrRange(cidr) {
  const [base, bitsText] = cidr.split('/');
  const bits = Number(bitsText);
  const start = ipToInt(base) & (bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0);
  const size = bits >= 31 ? 2 ** (32 - bits) : 2 ** (32 - bits) - 2;
  const first = bits >= 31 ? start : start + 1;
  return [first >>> 0, (first + Math.max(0, size - 1)) >>> 0];
}

/**
 * Pick random candidate IPs spread across the supplied ranges.
 *
 * NovaRadar caps a scan at 512 candidates, which is a sensible ceiling: past
 * that you are mostly waiting, not finding better IPs. Same default here.
 */
export function generateCandidates(cidrs, count = 512, random = Math.random) {
  const valid = cidrs.filter(isValidCidr);
  if (!valid.length) return [];

  const limit = Math.max(1, Math.min(4096, Math.floor(count)));
  const perRange = Math.max(1, Math.ceil(limit / valid.length));
  const seen = new Set();

  for (const cidr of valid) {
    const [first, last] = cidrRange(cidr);
    const span = last - first + 1;
    if (span <= 0) continue;
    for (let i = 0; i < perRange && seen.size < limit; i += 1) {
      seen.add(intToIp((first + Math.floor(random() * span)) >>> 0));
    }
    if (seen.size >= limit) break;
  }
  return [...seen];
}

/**
 * Build a ready-to-run scan plan for the desktop scanner.
 *
 * The Worker cannot test these itself, so the panel hands you the candidate
 * list and you verify it locally, then paste the winners back in.
 */
export async function buildScanPlan({
  count = 512, ports = [443], fetchImpl = fetch, refresh = false,
} = {}) {
  const ranges = await fetchCloudflareRanges(fetchImpl, { refresh });
  const chosen = ports.filter((port) => TLS_PORTS.includes(Number(port)));
  return {
    generatedAt: Date.now(),
    ranges: ranges.length,
    ports: chosen.length ? chosen : [443],
    candidates: generateCandidates(ranges, count),
  };
}
