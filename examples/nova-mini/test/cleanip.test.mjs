// Carrier detection, IP list parsing, pool resolution, and clean-IP configs.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  detectCarrier, parseIpList, resolvePool, pickIps, fetchRemotePool, CARRIER_CODES,
} from '../src/cleanip.js';
import { buildLinks, toClash, toSingBox } from '../src/subscription.js';

const req = (cf) => ({ cf });
const USER = { uuid: '89b3cbba-e6ac-485a-9481-976a0415eab9', token: 'tok' };

// ------------------------------------------------------------ detection

test('detects Irancell by ASN and by name', () => {
  assert.equal(detectCarrier(req({ country: 'IR', asn: 44244 })), 'mtn');
  assert.equal(detectCarrier(req({ country: 'IR', asOrganization: 'Irancell PJSC' })), 'mtn');
});

test('detects MCI by ASN and by name', () => {
  assert.equal(detectCarrier(req({ country: 'IR', asn: 197207 })), 'mci');
  assert.equal(
    detectCarrier(req({ country: 'IR', asOrganization: 'Mobile Communication Company of Iran' })),
    'mci',
  );
  assert.equal(detectCarrier(req({ country: 'IR', asOrganization: 'Hamrah-e-Avval' })), 'mci');
});

test('detects Rightel and Shatel', () => {
  assert.equal(detectCarrier(req({ country: 'IR', asn: 57218 })), 'rightel');
  assert.equal(detectCarrier(req({ country: 'IR', asn: 31549 })), 'shatel');
});

test('an unknown Iranian network falls back to ir', () => {
  assert.equal(detectCarrier(req({ country: 'IR', asn: 12345, asOrganization: 'Some ISP' })), 'ir');
});

test('outside Iran is always all', () => {
  assert.equal(detectCarrier(req({ country: 'DE', asn: 44244 })), 'all');
  assert.equal(detectCarrier(req({ country: 'US' })), 'all');
  assert.equal(detectCarrier(req({})), 'all');
  assert.equal(detectCarrier({}), 'all');
});

// ---------------------------------------------------------------- parsing

test('parses IPs with and without ports', () => {
  assert.deepEqual(parseIpList('1.2.3.4\n5.6.7.8:2053'), ['1.2.3.4', '5.6.7.8:2053']);
  assert.deepEqual(parseIpList('1.2.3.4, 5.6.7.8'), ['1.2.3.4', '5.6.7.8']);
});

test('drops comments, blanks, and trailing labels', () => {
  assert.deepEqual(parseIpList('# note\n\n1.2.3.4 #fast\n'), ['1.2.3.4']);
});

test('rejects malformed addresses and bad ports', () => {
  assert.deepEqual(parseIpList('999.1.1.1\n1.2.3\nnot-an-ip\n1.2.3.4:99999\nexample.com'), []);
});

test('accepts a valid boundary address', () => {
  assert.deepEqual(parseIpList('255.255.255.255:65535'), ['255.255.255.255:65535']);
});

test('caps the list length', () => {
  const many = Array.from({ length: 300 }, (_, i) => `1.2.3.${i % 256}`).join('\n');
  assert.equal(parseIpList(many).length, 200);
});

test('empty input is handled', () => {
  assert.deepEqual(parseIpList(''), []);
  assert.deepEqual(parseIpList(null), []);
  assert.deepEqual(parseIpList(undefined), []);
});

// -------------------------------------------------------------- resolution

test('a manual carrier list wins', async () => {
  const settings = { cleanIps: { mci: '1.1.1.1', all: '9.9.9.9' } };
  const { ips, source } = await resolvePool(settings, 'mci');
  assert.deepEqual(ips, ['1.1.1.1']);
  assert.equal(source, 'manual:mci');
});

test('falls back to ir then all', async () => {
  assert.equal((await resolvePool({ cleanIps: { ir: '2.2.2.2' } }, 'mci')).source, 'manual:ir');
  assert.equal((await resolvePool({ cleanIps: { all: '3.3.3.3' } }, 'mci')).source, 'manual:all');
});

test('nothing configured returns an empty pool', async () => {
  assert.deepEqual((await resolvePool({}, 'mci')).ips, []);
});

test('the remote pool is used when no manual list exists', async () => {
  const calls = [];
  const fakeFetch = async (url) => {
    calls.push(url);
    return { ok: url.endsWith('/mci.txt'), text: async () => '4.4.4.4\n5.5.5.5' };
  };
  const ips = await fetchRemotePool('https://example.com/pool', 'mci', fakeFetch);
  assert.deepEqual(ips, ['4.4.4.4', '5.5.5.5']);
  assert.equal(calls[0], 'https://example.com/pool/mci.txt');
});

test('a non-https pool URL is refused', async () => {
  let called = false;
  await fetchRemotePool('http://example.com/pool', 'mci', async () => { called = true; });
  assert.equal(called, false);
});

// ------------------------------------------------------------------ picking

test('picking returns at most the limit and is stable per seed', () => {
  const ips = Array.from({ length: 20 }, (_, i) => `1.2.3.${i}`);
  assert.equal(pickIps(ips, 8, 1).length, 8);
  assert.deepEqual(pickIps(ips, 8, 42), pickIps(ips, 8, 42));
  assert.notDeepEqual(pickIps(ips, 8, 1), pickIps(ips, 8, 9));
});

test('a short list is returned whole', () => {
  assert.deepEqual(pickIps(['1.1.1.1'], 8, 0), ['1.1.1.1']);
});

// ------------------------------------------------------- config generation

test('clean-IP links dial the IP but keep SNI on the domain', () => {
  const links = buildLinks(USER, { hosts: ['vpn.example.com'] }, 'x', ['1.2.3.4', '5.6.7.8:2053']);
  assert.equal(links.length, 2);
  assert.match(links[0], /^vless:\/\/[^@]+@1\.2\.3\.4:443\?/);
  assert.match(links[0], /sni=vpn\.example\.com/);
  assert.match(links[0], /host=vpn\.example\.com/);
  // the per-entry port is respected
  assert.match(links[1], /@5\.6\.7\.8:2053\?/);
});

test('without clean IPs the behaviour is unchanged', () => {
  const links = buildLinks(USER, { hosts: ['vpn.example.com'] }, 'x');
  assert.equal(links.length, 1);
  assert.match(links[0], /@vpn\.example\.com:443\?/);
});

test('clash output uses the IP as server and the domain as servername', () => {
  const yaml = toClash([], USER, { hosts: ['vpn.example.com'] }, 'x', ['1.2.3.4']);
  assert.match(yaml, /server: 1\.2\.3\.4/);
  assert.match(yaml, /servername: vpn\.example\.com/);
  assert.match(yaml, /Host: vpn\.example\.com/);
});

test('sing-box output does the same and stays valid JSON', () => {
  const parsed = JSON.parse(toSingBox([], USER, { hosts: ['vpn.example.com'] }, 'x', ['1.2.3.4:8443']));
  const out = parsed.outbounds.find((o) => o.type === 'vless');
  assert.equal(out.server, '1.2.3.4');
  assert.equal(out.server_port, 8443);
  assert.equal(out.tls.server_name, 'vpn.example.com');
});

test('every carrier code has a slot', () => {
  assert.deepEqual(CARRIER_CODES, ['mci', 'mtn', 'rightel', 'shatel', 'ir', 'all']);
});
