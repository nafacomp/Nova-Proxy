/**
 * Password hashing and session cookies.
 *
 * Passwords use PBKDF2-SHA256, which WebCrypto supports natively in Workers.
 * It is not Argon2, but with a high iteration count it is a reasonable choice
 * for a single-admin panel and needs no dependencies.
 */

import { readAdmin, writeAdmin } from './store.js';

const ITERATIONS = 210_000;      // OWASP guidance for PBKDF2-SHA256
const SESSION_MS = 12 * 60 * 60 * 1000;
const encoder = new TextEncoder();

export async function hashPassword(password, saltHex = randomHex(16)) {
  const salt = hexToBytes(saltHex);
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    key,
    256,
  );
  return { salt: saltHex, hash: bytesToHex(new Uint8Array(bits)), iterations: ITERATIONS };
}

export async function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false;
  const candidate = await hashPassword(password, record.salt);
  return timingSafeEqual(candidate.hash, record.hash);
}

/**
 * Session cookies are `expiry.signature`, signed with HMAC over the admin
 * hash. Changing the password therefore invalidates every existing session.
 */
export async function createSession(env, expiresAt = Date.now() + SESSION_MS, admin = null) {
  // Prefer the record we just wrote. Re-reading admin.json right after the
  // first PUT can return null because KV negatively-caches the earlier miss.
  const record = admin || await readAdmin(env, { allowReadyKey: true });
  if (!record?.hash) throw new Error('no admin configured');
  return `${expiresAt}.${await sign(env, record.hash, String(expiresAt))}`;
}

export async function verifySession(env, token) {
  if (!token || !token.includes('.')) return false;
  const [expiryText, signature] = token.split('.', 2);
  const expiresAt = Number(expiryText);
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return false;

  const admin = await readAdmin(env, { allowReadyKey: true });
  if (!admin) return false;
  return timingSafeEqual(signature, await sign(env, admin.hash, expiryText));
}

export async function isAuthenticated(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? verifySession(env, decodeURIComponent(match[1])) : false;
}

export function sessionCookie(token, maxAgeSeconds = SESSION_MS / 1000) {
  // HttpOnly blocks JS access, Secure forces HTTPS, SameSite=Strict stops CSRF.
  return `session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

export const clearedSessionCookie = 'session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';

export async function setAdminPassword(env, password) {
  const record = await hashPassword(password);
  const stored = { ...record, updatedAt: Date.now() };
  await writeAdmin(env, stored);
  return stored;
}

async function sign(env, secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return bytesToHex(new Uint8Array(mac));
}

/** Compares in constant time so a wrong guess cannot be timed. */
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function randomHex(bytes) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function randomUuid() {
  return crypto.randomUUID();
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const pairs = String(hex || '').match(/../g);
  if (!pairs) return new Uint8Array(0);
  return Uint8Array.from(pairs.map((h) => parseInt(h, 16)));
}
