// Verifies the VLESS header parser against hand-built byte sequences.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// The parser is internal, so pull it out of the source for testing.
const src = await readFile(new URL('../src/worker.js', import.meta.url), 'utf8');
// Strip the imports and the exported handler so the remaining helpers can be
// evaluated standalone. A data: URL cannot resolve relative imports, and the
// helpers under test do not need them.
const body = src
  .replace(/^import [\s\S]*?;$/gm, '')
  .replace(/^export default[\s\S]*?\n};$/m, '');
const mod = await import(
  'data:text/javascript,' +
  encodeURIComponent(body + '\nexport { readVlessHeader, bytesToUuid, splitHostPort };')
);
const { readVlessHeader, bytesToUuid, splitHostPort } = mod;

const UUID = '89b3cbba-e6ac-485a-9481-976a0415eab9';

const uuidBytes = (u) =>
  Uint8Array.from(u.replace(/-/g, '').match(/../g).map((h) => parseInt(h, 16)));

// Feed bytes as one chunk, or split across chunks to exercise buffering.
const readerOf = (...chunks) => {
  let i = 0;
  return {
    read: async () => (i < chunks.length ? { value: chunks[i++], done: false } : { value: undefined, done: true }),
    releaseLock() {},
  };
};

const build = ({ uuid = UUID, cmd = 1, port = 443, type = 2, host = 'example.com', payload = [1, 2, 3] }) => {
  const addr = type === 1 ? host.split('.').map(Number)
    : type === 2 ? [host.length, ...new TextEncoder().encode(host)]
    : Array.from({ length: 16 }, (_, i) => i);
  return Uint8Array.from([0, ...uuidBytes(uuid), 0, cmd, port >> 8, port & 255, type, ...addr, ...payload]);
};

test('parses a domain target', async () => {
  const h = await readVlessHeader(readerOf(build({})), UUID);
  assert.equal(h.host, 'example.com');
  assert.equal(h.port, 443);
  assert.deepEqual([...h.payload], [1, 2, 3]);
});

test('parses an IPv4 target', async () => {
  const h = await readVlessHeader(readerOf(build({ type: 1, host: '1.2.3.4', port: 80 })), UUID);
  assert.equal(h.host, '1.2.3.4');
  assert.equal(h.port, 80);
});

test('parses an IPv6 target', async () => {
  const h = await readVlessHeader(readerOf(build({ type: 3 })), UUID);
  assert.equal(h.host, '[1:203:405:607:809:a0b:c0d:e0f]');
});

test('reassembles a header split across chunks', async () => {
  const full = build({});
  const h = await readVlessHeader(readerOf(full.subarray(0, 5), full.subarray(5, 20), full.subarray(20)), UUID);
  assert.equal(h.host, 'example.com');
  assert.deepEqual([...h.payload], [1, 2, 3]);
});

test('rejects the wrong uuid', async () => {
  await assert.rejects(
    () => readVlessHeader(readerOf(build({})), '00000000-0000-4000-8000-000000000000'),
    /uuid mismatch/,
  );
});

test('rejects the UDP command', async () => {
  await assert.rejects(() => readVlessHeader(readerOf(build({ cmd: 2 })), UUID), /only the TCP command/);
});

test('rejects a truncated header', async () => {
  await assert.rejects(() => readVlessHeader(readerOf(build({}).subarray(0, 10)), UUID), /stream ended/);
});

test('round-trips a uuid', () => {
  assert.equal(bytesToUuid(uuidBytes(UUID)), UUID);
});

test('splits host and port forms', () => {
  assert.deepEqual(splitHostPort('1.2.3.4', 443), ['1.2.3.4', 443]);
  assert.deepEqual(splitHostPort('1.2.3.4:8443', 443), ['1.2.3.4', 8443]);
  assert.deepEqual(splitHostPort('[::1]:2053', 443), ['::1', 2053]);
  assert.deepEqual(splitHostPort('proxy.example.com', 443), ['proxy.example.com', 443]);
});
