/**
 * Admin routes, the subscription endpoint, and their guards.
 *
 * Every /admin route except the login and first-run setup pages requires a
 * valid session. Subscription links are unauthenticated by design, so the
 * token in the URL is the credential.
 */

import {
  isAuthenticated, verifyPassword, createSession, sessionCookie,
  clearedSessionCookie, setAdminPassword, randomHex, randomUuid, timingSafeEqual,
} from './auth.js';
import { readUsers, writeUsers, readSettings, writeSettings, readAdmin } from './store.js';
import { loginPage, setupPage, dashboardPage } from './panel.js';
import { buildLinks, toBase64, toClash, toSingBox, chooseFormat, contentTypeFor } from './subscription.js';
import { detectCarrier, resolvePool, pickIps, parseIpList, CARRIER_CODES, CARRIER_LABELS } from './cleanip.js';
import { buildScanPlan, TLS_PORTS } from './cidr.js';

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' },
});

const html = (body, status = 200, headers = {}) => new Response(body, {
  status,
  headers: {
    'Content-Type': 'text/html;charset=utf-8',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    // The panel's only inline script is our own; nothing loads from outside.
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'",
    ...headers,
  },
});

/** Stable per-user seed so a user keeps the same slice of the pool. */
function hashSeed(text) {
  let hash = 0;
  for (let i = 0; i < String(text).length; i += 1) {
    hash = (hash * 31 + String(text).charCodeAt(i)) >>> 0;
  }
  return hash;
}

/** Simple per-IP throttle so the login form cannot be brute forced. */
const attempts = new Map();
const MAX_ATTEMPTS = 6;
const WINDOW_MS = 10 * 60 * 1000;

function throttled(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || now - entry.first > WINDOW_MS) return false;
  return entry.count >= MAX_ATTEMPTS;
}

function noteFailure(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || now - entry.first > WINDOW_MS) attempts.set(ip, { count: 1, first: now });
  else entry.count += 1;

  if (attempts.size > 1000) {
    for (const [key, value] of attempts) {
      if (now - value.first > WINDOW_MS) attempts.delete(key);
      if (attempts.size <= 500) break;
    }
  }
}

function clearFailures(request) {
  attempts.delete(request.headers.get('CF-Connecting-IP') || 'unknown');
}

/**
 * Routes anything that is not a WebSocket upgrade.
 * Returns null when the path is unknown, so the caller can 404.
 */
export async function handleHttp(request, env, url) {
  const path = url.pathname.replace(/\/+$/, '') || '/';

  if (path === '/sub' || path.startsWith('/sub/')) return handleSubscription(request, env, url, path);
  if (path === '/admin' || path.startsWith('/admin/')) return handleAdmin(request, env, url, path);
  return null;
}

async function handleSubscription(request, env, url, path) {
  const token = path.startsWith('/sub/') ? path.slice(5) : url.searchParams.get('token') || '';
  if (!token) return new Response('Not found', { status: 404 });

  const users = await readUsers(env);
  // Compare against every user so a wrong token costs the same time as a right one.
  const user = users.find((candidate) => timingSafeEqual(candidate.token, token));
  if (!user || user.enabled === false) return new Response('Not found', { status: 404 });

  const settings = await readSettings(env);

  // Which carrier is this subscription being fetched from? request.cf is set
  // by Cloudflare and cannot be spoofed by the client.
  const carrier = String(url.searchParams.get('carrier') || '').toLowerCase();
  const detected = CARRIER_CODES.includes(carrier) ? carrier : detectCarrier(request);

  let cleanIps = [];
  if (settings.cleanIpEnabled !== false) {
    const pool = await resolvePool(settings, detected);
    cleanIps = pickIps(pool.ips, Number(settings.cleanIpCount) || 8, hashSeed(user.token));
  }

  const links = buildLinks(user, settings, url.hostname, cleanIps);
  const format = chooseFormat(url, request.headers.get('User-Agent') || '');

  const body = format === 'clash' ? toClash(links, user, settings, url.hostname, cleanIps)
    : format === 'singbox' ? toSingBox(links, user, settings, url.hostname, cleanIps)
    : toBase64(links);

  return new Response(body, {
    headers: {
      'Content-Type': contentTypeFor(format),
      'Cache-Control': 'no-store',
      'Profile-Update-Interval': '12',
      'X-Nova-Carrier': detected,
      'Subscription-Userinfo': 'upload=0; download=0; total=0',
      'Content-Disposition': `attachment; filename="${settings.subName || 'nova-mini'}"`,
    },
  });
}

async function handleAdmin(request, env, url, path) {
  const admin = await readAdmin(env);

  // First run: let the operator claim the panel. A CLAIM_TOKEN, when set,
  // stops a stranger who finds the URL first from claiming it.
  if (!admin) {
    if (path === '/admin/setup' && request.method === 'POST') {
      const claim = String(env.CLAIM_TOKEN || '');
      if (claim && !timingSafeEqual(url.searchParams.get('claim') || '', claim)) {
        return html(setupPage('Add ?claim=<your CLAIM_TOKEN> to this URL.'), 403);
      }
      const form = await request.formData();
      const password = String(form.get('password') || '');
      if (password.length < 10) return html(setupPage('Use at least 10 characters.'), 400);

      await setAdminPassword(env, password);
      return new Response(null, {
        status: 303,
        headers: { Location: '/admin', 'Set-Cookie': sessionCookie(await createSession(env)) },
      });
    }
    return html(setupPage());
  }

  if (path === '/admin/login' && request.method === 'POST') {
    if (throttled(request)) return html(loginPage('Too many attempts. Wait a few minutes.'), 429);

    const form = await request.formData();
    if (!(await verifyPassword(String(form.get('password') || ''), admin))) {
      noteFailure(request);
      return html(loginPage('Wrong password.'), 401);
    }
    clearFailures(request);
    return new Response(null, {
      status: 303,
      headers: { Location: '/admin', 'Set-Cookie': sessionCookie(await createSession(env)) },
    });
  }

  if (path === '/admin/logout' && request.method === 'POST') {
    return new Response(null, { status: 303, headers: { Location: '/admin', 'Set-Cookie': clearedSessionCookie } });
  }

  const signedIn = await isAuthenticated(request, env);
  if (!signedIn) {
    if (path.startsWith('/admin/api/')) return json({ error: 'unauthorized' }, 401);
    return html(loginPage());
  }

  if (path === '/admin') return html(dashboardPage());
  if (path.startsWith('/admin/api/')) return handleApi(request, env, path);
  return new Response('Not found', { status: 404 });
}

async function handleApi(request, env, path) {
  // Reject cross-origin writes outright; the panel only ever calls itself.
  if (request.method !== 'GET') {
    const origin = request.headers.get('Origin');
    if (origin && new URL(origin).origin !== new URL(request.url).origin) {
      return json({ error: 'cross-origin request rejected' }, 403);
    }
  }

  // Shows the operator which carrier Cloudflare thinks they are on, which is
  // the quickest way to check the detection is working.
  if (path === '/admin/api/whoami' && request.method === 'GET') {
    const cf = request.cf || {};
    const carrier = detectCarrier(request);
    return json({
      carrier,
      label: CARRIER_LABELS[carrier] || carrier,
      country: cf.country || null,
      asn: cf.asn || null,
      org: cf.asOrganization || null,
    });
  }

  // Candidate IPs to verify with a desktop scanner. A Worker cannot test
  // these itself: Cloudflare's SSRF sandbox blocks raw TCP to a bare IP.
  if (path === '/admin/api/scan-plan' && request.method === 'GET') {
    const url = new URL(request.url);
    const count = Math.max(16, Math.min(2048, Number(url.searchParams.get('count')) || 512));
    const port = Number(url.searchParams.get('port')) || 443;
    const plan = await buildScanPlan({
      count,
      ports: [TLS_PORTS.includes(port) ? port : 443],
    });
    return json(plan);
  }

  // Same list as plain text, ready to feed straight into a scanner.
  if (path === '/admin/api/scan-plan.txt' && request.method === 'GET') {
    const url = new URL(request.url);
    const count = Math.max(16, Math.min(2048, Number(url.searchParams.get('count')) || 512));
    const port = Number(url.searchParams.get('port')) || 443;
    const chosen = TLS_PORTS.includes(port) ? port : 443;
    const plan = await buildScanPlan({ count, ports: [chosen] });
    return new Response(plan.candidates.map((ip) => `${ip}:${chosen}`).join('\n') + '\n', {
      headers: {
        'Content-Type': 'text/plain;charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Disposition': 'attachment; filename="scan-candidates.txt"',
      },
    });
  }

  if (path === '/admin/api/state' && request.method === 'GET') {
    const [users, settings] = await Promise.all([readUsers(env), readSettings(env)]);
    return json({ users, settings });
  }

  if (path === '/admin/api/users' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const name = String(body.name || '').trim().slice(0, 40);
    if (!name) return json({ error: 'name is required' }, 400);

    const users = await readUsers(env);
    const max = Number(env.MAX_USERS) || 10;
    if (users.length >= max) return json({ error: `user limit of ${max} reached` }, 400);

    users.push({
      id: randomHex(8),
      name,
      uuid: randomUuid(),
      token: randomHex(16),
      enabled: true,
      createdAt: Date.now(),
    });
    await writeUsers(env, users);
    return json({ ok: true });
  }

  const deleteMatch = path.match(/^\/admin\/api\/users\/([\w-]+)$/);
  if (deleteMatch && request.method === 'DELETE') {
    const users = await readUsers(env);
    const remaining = users.filter((user) => user.id !== deleteMatch[1]);
    if (remaining.length === users.length) return json({ error: 'user not found' }, 404);
    await writeUsers(env, remaining);
    return json({ ok: true });
  }

  if (path === '/admin/api/settings' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const hosts = Array.isArray(body.hosts)
      ? body.hosts.map((h) => String(h).trim().toLowerCase()
          .replace(/^https?:\/\//, '').split('/')[0]).filter(Boolean).slice(0, 10)
      : [];
    // Keep only the known carrier keys, and validate every IP on the way in
    // so a typo cannot end up in a subscription.
    const cleanIps = {};
    if (body.cleanIps && typeof body.cleanIps === 'object') {
      for (const code of CARRIER_CODES) {
        const parsed = parseIpList(body.cleanIps[code]);
        if (parsed.length) cleanIps[code] = parsed.join('\n');
      }
    }
    const poolApi = String(body.poolApi || '').trim();
    if (poolApi && !/^https:\/\//i.test(poolApi)) {
      return json({ error: 'the pool URL must start with https://' }, 400);
    }

    await writeSettings(env, {
      hosts,
      port: Number(body.port) || 443,
      subName: String(body.subName || '').trim().slice(0, 40),
      cleanIps,
      poolApi,
      cleanIpEnabled: body.cleanIpEnabled !== false,
      cleanIpCount: Math.max(1, Math.min(32, Number(body.cleanIpCount) || 8)),
    });
    return json({ ok: true });
  }

  if (path === '/admin/api/password' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const password = String(body.password || '');
    if (password.length < 10) return json({ error: 'use at least 10 characters' }, 400);
    // Sessions are signed with the password hash, so this invalidates them all.
    await setAdminPassword(env, password);
    return json({ ok: true });
  }

  return json({ error: 'not found' }, 404);
}
