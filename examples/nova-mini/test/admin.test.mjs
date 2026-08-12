// First-run setup: CLAIM_TOKEN on the form, and Cloudflare KV's negative cache.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { handleHttp } from '../src/admin.js';
import { setupPage } from '../src/panel.js';
import { createSession, setAdminPassword } from '../src/auth.js';
import { readAdmin } from '../src/store.js';

const CLAIM = 'a3f8c21d94b7e05f6c8a1d2e3f4b5c6d';
const PASSWORD = 'correct-horse-battery';

const memoryKv = () => {
  const map = new Map();
  return {
    map,
    get: async (k) => (map.has(k) ? map.get(k) : null),
    put: async (k, v) => { map.set(k, v); },
  };
};

/** GET of a missing key stays null even after PUT — Cloudflare KV's first-run trap. */
const negativeCacheKv = () => {
  const map = new Map();
  const missed = new Set();
  return {
    map,
    get: async (k) => {
      if (missed.has(k)) return null;
      if (!map.has(k)) {
        missed.add(k);
        return null;
      }
      return map.get(k);
    },
    put: async (k, v) => { map.set(k, v); },
  };
};

const envOf = (kv, extras = {}) => ({ KV: kv, CLAIM_TOKEN: extras.claim ?? CLAIM, ...extras });

const get = (path) => new Request(`https://edge.example.com${path}`);

const post = (path, body) => new Request(`https://edge.example.com${path}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body,
});

test('the setup form keeps ?claim= on submit', () => {
  const page = setupPage('', CLAIM);
  assert.match(page, /action="\/admin\/setup\?claim=a3f8c21d94b7e05f6c8a1d2e3f4b5c6d"/);
  assert.match(page, /name="claim" value="a3f8c21d94b7e05f6c8a1d2e3f4b5c6d"/);
});

test('GET /admin/setup without the claim is rejected when CLAIM_TOKEN is set', async () => {
  const res = await handleHttp(get('/admin/setup'), envOf(memoryKv()), new URL('https://edge.example.com/admin/setup'));
  assert.equal(res.status, 403);
  assert.match(await res.text(), /Add \?claim=/);
});

test('GET /admin/setup with the claim shows the password form', async () => {
  const url = new URL(`https://edge.example.com/admin/setup?claim=${CLAIM}`);
  const res = await handleHttp(get(url.pathname + url.search), envOf(memoryKv()), url);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /Create your admin password/);
  assert.match(body, new RegExp(`action="/admin/setup\\?claim=${CLAIM}"`));
});

test('POST /admin/setup without the claim is rejected', async () => {
  const url = new URL('https://edge.example.com/admin/setup');
  const res = await handleHttp(post('/admin/setup', `password=${PASSWORD}`), envOf(memoryKv()), url);
  assert.equal(res.status, 403);
  assert.match(await res.text(), /Add \?claim=/);
});

test('POST /admin/setup accepts the claim from the form body', async () => {
  const url = new URL('https://edge.example.com/admin/setup');
  const res = await handleHttp(
    post('/admin/setup', `password=${encodeURIComponent(PASSWORD)}&claim=${CLAIM}`),
    envOf(memoryKv()),
    url,
  );
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('Location'), '/admin');
  assert.match(res.headers.get('Set-Cookie') || '', /session=/);
});

test('first-run POST still signs in when KV negatively-caches admin.json', async () => {
  const kv = negativeCacheKv();
  const env = envOf(kv);

  // Same sequence as a browser: open the form (caches the miss), then submit.
  const setupUrl = new URL(`https://edge.example.com/admin/setup?claim=${CLAIM}`);
  const form = await handleHttp(get(setupUrl.pathname + setupUrl.search), env, setupUrl);
  assert.equal(form.status, 200);

  const posted = await handleHttp(
    post(setupUrl.pathname + setupUrl.search, `password=${encodeURIComponent(PASSWORD)}`),
    env,
    setupUrl,
  );
  assert.equal(posted.status, 303, 'must not throw / return Bad request');
  const cookie = posted.headers.get('Set-Cookie') || '';
  assert.match(cookie, /session=/);

  // admin.json itself is still a cached miss; the ready key must be readable.
  assert.equal(await kv.get('admin.json'), null);
  assert.ok(await kv.get('admin-ready.json'));
  assert.equal(await readAdmin(env), null);
  assert.ok(await readAdmin(env, { allowReadyKey: true }));

  const session = cookie.match(/session=([^;]+)/)[1];
  const next = await handleHttp(
    new Request('https://edge.example.com/admin', { headers: { Cookie: `session=${session}` } }),
    env,
    new URL('https://edge.example.com/admin'),
  );
  assert.equal(next.status, 200);
  assert.match(await next.text(), /nova-mini/);
});

test('createSession can use the record just written, without re-reading KV', async () => {
  const kv = negativeCacheKv();
  const env = envOf(kv, { claim: '' });
  await readAdmin(env); // populate the negative cache
  const record = await setAdminPassword(env, PASSWORD);
  assert.equal(await readAdmin(env), null);
  const token = await createSession(env, undefined, record);
  assert.match(token, /^\d+\.[0-9a-f]+$/);
});
