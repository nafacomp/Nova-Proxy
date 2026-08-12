/**
 * Iranian carrier detection and clean-IP pools.
 *
 * Cloudflare's anycast edge is reachable on a huge range of IPs, but on
 * Iranian mobile networks only some of them are fast or reachable at all, and
 * which ones differ per carrier. This module lets the panel hand each user a
 * list picked for their own operator.
 *
 * Detection uses `request.cf`, which Cloudflare fills in and a client cannot
 * forge, so a user cannot talk their way into another carrier's pool.
 *
 * Every source is operator-supplied. Nothing here contacts a fixed upstream:
 * you either paste IPs into the panel or point it at a URL you control.
 */

/**
 * AS numbers for the major Iranian networks, taken from the upstream panel's
 * own detection logic so behaviour matches what users already expect.
 */
const CARRIERS = [
  { code: 'mtn', asn: 44244, match: /irancell|mtn/ },
  { code: 'mci', asn: 197207, match: /mobile communication company of iran|mcci|hamrah/ },
  { code: 'rightel', asn: 57218, match: /rightel/ },
  { code: 'shatel', asn: 31549, match: /shatel/ },
];

export const CARRIER_CODES = ['mci', 'mtn', 'rightel', 'shatel', 'ir', 'all'];

/** Human labels for the panel. */
export const CARRIER_LABELS = {
  mci: 'همراه اول (MCI)',
  mtn: 'ایرانسل (MTN)',
  rightel: 'رایتل',
  shatel: 'شاتل',
  ir: 'سایر اپراتورهای ایران',
  all: 'خارج از ایران / پیش‌فرض',
};

/**
 * Work out which pool a request belongs to.
 *   'all'  -> not in Iran, use the default pool
 *   'ir'   -> in Iran but an unrecognised network
 *   others -> a specific carrier
 */
export function detectCarrier(request) {
  const cf = request?.cf || {};
  if (String(cf.country || '').toUpperCase() !== 'IR') return 'all';

  const org = String(cf.asOrganization || '').toLowerCase();
  const asn = Number(cf.asn || 0);

  for (const carrier of CARRIERS) {
    if (asn === carrier.asn || carrier.match.test(org)) return carrier.code;
  }
  return 'ir';
}

/**
 * Accepts either "1.2.3.4" or "1.2.3.4:8443", one per line or comma
 * separated, and ignores blank lines and # comments. Anything that is not a
 * valid IPv4 (with an in-range port) is dropped rather than silently shipped
 * to a client that cannot use it.
 */
export function parseIpList(text) {
  if (!text) return [];
  return String(text)
    .split(/[\n,]+/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => line.split('#')[0].trim())
    .filter((entry) => isValidEntry(entry))
    .slice(0, 200);                       // keep subscriptions a sane size
}

function isValidEntry(entry) {
  const [host, port] = splitEntry(entry);
  if (port !== null && !(port > 0 && port <= 65535)) return false;
  const octets = host.split('.');
  if (octets.length !== 4) return false;
  return octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function splitEntry(entry) {
  const index = entry.lastIndexOf(':');
  if (index === -1) return [entry, null];
  return [entry.slice(0, index), Number(entry.slice(index + 1))];
}

/** Cache remote lists briefly so a busy panel does not refetch per request. */
const remoteCache = new Map();
const REMOTE_TTL_MS = 30 * 60 * 1000;

/**
 * Fetch a carrier list from a URL the operator configured.
 *
 * `baseUrl` is treated as a folder holding one file per carrier
 * (mci.txt, mtn.txt, ...), matching the layout Nova Radar exports, so an
 * existing list can be reused. Falls back to ir.txt then all.txt.
 */
export async function fetchRemotePool(baseUrl, carrier, fetchImpl = fetch) {
  const base = String(baseUrl || '').trim().replace(/\/+$/, '');
  if (!/^https:\/\//i.test(base)) return [];

  const candidates = [...new Set([carrier, 'ir', 'all'])];
  for (const name of candidates) {
    const url = `${base}/${name}.txt`;
    const cached = remoteCache.get(url);
    if (cached && Date.now() - cached.at < REMOTE_TTL_MS) {
      if (cached.ips.length) return cached.ips.slice();
      continue;
    }
    try {
      const response = await fetchImpl(url, {
        headers: { 'User-Agent': 'nova-mini' },
        cf: { cacheTtl: 1800, cacheEverything: true },
      });
      const ips = response.ok ? parseIpList(await response.text()) : [];
      remoteCache.set(url, { at: Date.now(), ips });
      if (ips.length) return ips.slice();
    } catch {
      remoteCache.set(url, { at: Date.now(), ips: [] });
    }
  }
  return [];
}

/**
 * Resolve the clean IPs for one request.
 *
 * Manual lists win over the remote source, so a list you paste in the panel
 * is always authoritative. Returns [] when nothing is configured, and the
 * caller then falls back to the plain hostname.
 */
export async function resolvePool(settings, carrier, fetchImpl = fetch) {
  const pools = settings?.cleanIps || {};

  const manual = parseIpList(pools[carrier]);
  if (manual.length) return { ips: manual, source: `manual:${carrier}` };

  for (const fallback of ['ir', 'all']) {
    const list = parseIpList(pools[fallback]);
    if (list.length) return { ips: list, source: `manual:${fallback}` };
  }

  if (settings?.poolApi) {
    const remote = await fetchRemotePool(settings.poolApi, carrier, fetchImpl);
    if (remote.length) return { ips: remote, source: `remote:${carrier}` };
  }

  return { ips: [], source: 'none' };
}

/**
 * Spread picks across the list instead of always taking the first N, so
 * every user does not hammer the same handful of addresses.
 */
export function pickIps(ips, limit = 8, seed = Date.now()) {
  if (ips.length <= limit) return ips.slice();
  const start = Math.abs(Math.floor(seed)) % ips.length;
  const out = [];
  for (let i = 0; i < limit; i += 1) out.push(ips[(start + i) % ips.length]);
  return out;
}
