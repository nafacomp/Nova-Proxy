// Covers the panel pieces: password hashing, sessions, subscription output,
// and multi-user uuid matching.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  hashPassword, verifyPassword, timingSafeEqual, randomHex,
  createSession, verifySession,
} from '../src/auth.js';
import { buildLinks, toBase64, toClash, toSingBox, chooseFormat } from '../src/subscription.js';
import { readUsers, writeUsers, readSettings, writeSettings } from '../src/store.js';

/** Minimal in-memory stand-in for a KV namespace. */
const fakeEnv = () => {
  const map = new Map();
  return {
    KV: {
      get: async (k) => (map.has(k) ? map.get(k) : null),
      put: async (k, v) => { map.set(k, v); },
    },
  };
};

const USER = { id: 'u1', name: 'phone', uuid: '89b3cbba-e6ac-485a-9481-976a0415eab9', token: 'abc123', enabled: true };

// ---------------------------------------------------------------- passwords

test('a correct password verifies', async () => {
  const record = await hashPassword('correct horse battery');
  assert.equal(await verifyPassword('correct horse battery', record), true);
});

test('a wrong password is rejected', async () => {
  const record = await hashPassword('correct horse battery');
  assert.equal(await verifyPassword('wrong password here', record), false);
});

test('the same password gets a different salt each time', async () => {
  const a = await hashPassword('same-input');
  const b = await hashPassword('same-input');
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.hash, b.hash);   // salted, so hashes differ too
});

test('verification tolerates a missing record', async () => {
  assert.equal(await verifyPassword('x', null), false);
  assert.equal(await verifyPassword('x', {}), false);
});

test('timingSafeEqual compares correctly', () => {
  assert.equal(timingSafeEqual('abc', 'abc'), true);
  assert.equal(timingSafeEqual('abc', 'abd'), false);
  assert.equal(timingSafeEqual('abc', 'abcd'), false);   // length differs
  assert.equal(timingSafeEqual('abc', null), false);
});

// ----------------------------------------------------------------- sessions

test('a fresh session verifies', async () => {
  const env = fakeEnv();
  await env.KV.put('admin.json', JSON.stringify(await hashPassword('pw-for-session')));
  assert.equal(await verifySession(env, await createSession(env)), true);
});

test('an expired session is rejected', async () => {
  const env = fakeEnv();
  await env.KV.put('admin.json', JSON.stringify(await hashPassword('pw-for-session')));
  const expired = await createSession(env, Date.now() - 1000);
  assert.equal(await verifySession(env, expired), false);
});

test('a tampered session is rejected', async () => {
  const env = fakeEnv();
  await env.KV.put('admin.json', JSON.stringify(await hashPassword('pw-for-session')));
  const token = await createSession(env);
  const [expiry] = token.split('.');
  // Forge a far-future expiry with the original signature.
  assert.equal(await verifySession(env, `${Number(expiry) + 999999}.${token.split('.')[1]}`), false);
});

test('changing the password invalidates existing sessions', async () => {
  const env = fakeEnv();
  await env.KV.put('admin.json', JSON.stringify(await hashPassword('first-password')));
  const token = await createSession(env);
  assert.equal(await verifySession(env, token), true);

  await env.KV.put('admin.json', JSON.stringify(await hashPassword('second-password')));
  assert.equal(await verifySession(env, token), false);
});

test('malformed session tokens are rejected', async () => {
  const env = fakeEnv();
  await env.KV.put('admin.json', JSON.stringify(await hashPassword('pw')));
  for (const bad of ['', 'nodot', 'abc.def', '.', 'NaN.xyz']) {
    assert.equal(await verifySession(env, bad), false, `expected ${JSON.stringify(bad)} to fail`);
  }
});

// ------------------------------------------------------------ subscriptions

test('a vless link carries the right uuid, host, and port', () => {
  const [link] = buildLinks(USER, {}, 'edge.example.com');
  assert.match(link, /^vless:\/\/89b3cbba-e6ac-485a-9481-976a0415eab9@edge\.example\.com:443\?/);
  assert.match(link, /type=ws/);
  assert.match(link, /security=tls/);
});

test('configured hosts produce one link each', () => {
  const links = buildLinks(USER, { hosts: ['a.example.com', 'b.example.com'] }, 'ignored.example.com');
  assert.equal(links.length, 2);
  assert.match(links[0], /a\.example\.com/);
  assert.match(links[1], /b\.example\.com/);
});

test('an invalid port falls back to 443', () => {
  const [link] = buildLinks(USER, { port: 9999 }, 'edge.example.com');
  assert.match(link, /:443\?/);
});

test('base64 output round-trips', () => {
  const links = buildLinks(USER, {}, 'edge.example.com');
  const decoded = Buffer.from(toBase64(links), 'base64').toString('utf8');
  assert.equal(decoded, links.join('\n'));
});

test('clash output mentions the uuid and server', () => {
  const yaml = toClash(buildLinks(USER, {}, 'edge.example.com'), USER, {}, 'edge.example.com');
  assert.match(yaml, /type: vless/);
  assert.match(yaml, /uuid: 89b3cbba-e6ac-485a-9481-976a0415eab9/);
  assert.match(yaml, /server: edge\.example\.com/);
  assert.match(yaml, /proxy-groups:/);
});

test('sing-box output is valid JSON with an outbound', () => {
  const raw = toSingBox(buildLinks(USER, {}, 'edge.example.com'), USER, {}, 'edge.example.com');
  const parsed = JSON.parse(raw);
  const vless = parsed.outbounds.find((o) => o.type === 'vless');
  assert.equal(vless.uuid, USER.uuid);
  assert.equal(vless.server, 'edge.example.com');
  assert.equal(vless.transport.type, 'ws');
});

test('the format is chosen from the query string or user agent', () => {
  const url = (q = '') => new URL(`https://x.example.com/sub/tok${q}`);
  assert.equal(chooseFormat(url('?format=clash'), ''), 'clash');
  assert.equal(chooseFormat(url(), 'clash-verge/1.0'), 'clash');
  assert.equal(chooseFormat(url(), 'mihomo/1.0'), 'clash');
  assert.equal(chooseFormat(url(), 'sing-box/1.8'), 'singbox');
  assert.equal(chooseFormat(url(), 'v2rayN/6.0'), 'base64');
  assert.equal(chooseFormat(url(), ''), 'base64');
  // An explicit parameter wins over the user agent.
  assert.equal(chooseFormat(url('?format=base64'), 'clash'), 'base64');
});

// -------------------------------------------------------------------- store

test('users and settings survive a write and read', async () => {
  const env = fakeEnv();
  assert.deepEqual(await readUsers(env), []);

  await writeUsers(env, [USER]);
  assert.equal((await readUsers(env))[0].uuid, USER.uuid);

  await writeSettings(env, { hosts: ['x.example.com'], port: 2053 });
  assert.equal((await readSettings(env)).port, 2053);
});

test('corrupt stored JSON falls back instead of throwing', async () => {
  const env = fakeEnv();
  // readUsers caches, so assert on settings, which is read fresh every call.
  await env.KV.put('settings.json', '{not valid json');
  assert.deepEqual(await readSettings(env), {});

  // And confirm a valid write still parses afterwards.
  await writeSettings(env, { port: 8443 });
  assert.equal((await readSettings(env)).port, 8443);
});

test('random hex has the requested length and varies', () => {
  assert.equal(randomHex(16).length, 32);
  assert.notEqual(randomHex(16), randomHex(16));
});
