/**
 * Storage layer. Everything lives in one KV namespace bound as `KV`.
 *
 * KV is eventually consistent, which is fine here: a few seconds of lag on a
 * settings change is harmless, and the tunnel reads users through a short
 * in-memory cache anyway.
 */

const USERS_KEY = 'users.json';
const SETTINGS_KEY = 'settings.json';
const ADMIN_KEY = 'admin.json';
// Written together with ADMIN_KEY. First-run GET never reads this key, so
// Cloudflare's ~60s negative cache on a missing admin.json cannot hide a
// password that was just created (the setup POST then 303 to /admin).
const ADMIN_READY_KEY = 'admin-ready.json';

/** Reads are hot on the tunnel path, so cache briefly inside the isolate. */
let userCache = null;
let userCacheAt = 0;
const USER_CACHE_MS = 10_000;

export async function readUsers(env) {
  const now = Date.now();
  if (userCache && now - userCacheAt < USER_CACHE_MS) return userCache;
  const raw = await env.KV.get(USERS_KEY);
  userCache = safeParse(raw, []);
  userCacheAt = now;
  return userCache;
}

export async function writeUsers(env, users) {
  await env.KV.put(USERS_KEY, JSON.stringify(users));
  userCache = users;
  userCacheAt = Date.now();
}

export async function readSettings(env) {
  return safeParse(await env.KV.get(SETTINGS_KEY), {});
}

export async function writeSettings(env, settings) {
  await env.KV.put(SETTINGS_KEY, JSON.stringify(settings));
}

export async function readAdmin(env, { allowReadyKey = false } = {}) {
  const raw = await env.KV.get(ADMIN_KEY);
  if (raw) return safeParse(raw, null);
  if (!allowReadyKey) return null;
  return safeParse(await env.KV.get(ADMIN_READY_KEY), null);
}

export async function writeAdmin(env, admin) {
  const payload = JSON.stringify(admin);
  await Promise.all([
    env.KV.put(ADMIN_KEY, payload),
    env.KV.put(ADMIN_READY_KEY, payload),
  ]);
}

function safeParse(raw, fallback) {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}
