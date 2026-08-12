// CIDR parsing, range maths, and candidate generation.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  CLOUDFLARE_V4, TLS_PORTS, parseCidrList, isValidCidr, ipToInt, intToIp,
  cidrRange, generateCandidates, fetchCloudflareRanges, buildScanPlan,
} from '../src/cidr.js';

test('the built-in ranges are all valid CIDRs', () => {
  assert.ok(CLOUDFLARE_V4.length >= 15);
  for (const cidr of CLOUDFLARE_V4) assert.ok(isValidCidr(cidr), `${cidr} should be valid`);
});

test('CIDR validation rejects malformed input', () => {
  for (const bad of ['1.2.3.4', '1.2.3.4/33', '999.1.1.1/24', '1.2.3/24', 'nope', '', null]) {
    assert.equal(isValidCidr(bad), false, `${bad} should be invalid`);
  }
  assert.equal(isValidCidr('104.16.0.0/13'), true);
  assert.equal(isValidCidr('0.0.0.0/0'), true);
});

test('ip and integer conversion round-trips', () => {
  for (const ip of ['0.0.0.0', '1.2.3.4', '104.16.0.1', '255.255.255.255']) {
    assert.equal(intToIp(ipToInt(ip)), ip);
  }
});

test('cidrRange skips network and broadcast', () => {
  const [first, last] = cidrRange('192.168.1.0/24');
  assert.equal(intToIp(first), '192.168.1.1');     // not .0
  assert.equal(intToIp(last), '192.168.1.254');    // not .255
});

test('cidrRange handles /31 and /32', () => {
  assert.equal(intToIp(cidrRange('10.0.0.0/31')[0]), '10.0.0.0');
  const [a, b] = cidrRange('10.0.0.5/32');
  assert.equal(intToIp(a), '10.0.0.5');
  assert.equal(a, b);
});

test('cidrRange normalises a non-aligned base address', () => {
  // 104.16.5.7/16 should still start at 104.16.0.1
  assert.equal(intToIp(cidrRange('104.16.5.7/16')[0]), '104.16.0.1');
});

test('parseCidrList keeps valid entries and drops junk', () => {
  const text = '104.16.0.0/13\n# comment\nnot-a-cidr\n\n172.64.0.0/13\n1.2.3.4\n';
  assert.deepEqual(parseCidrList(text), ['104.16.0.0/13', '172.64.0.0/13']);
});

test('candidates are generated inside the requested range', () => {
  const ips = generateCandidates(['192.168.1.0/24'], 20);
  assert.ok(ips.length > 0 && ips.length <= 20);
  for (const ip of ips) {
    assert.match(ip, /^192\.168\.1\.\d+$/);
    const last = Number(ip.split('.')[3]);
    assert.ok(last >= 1 && last <= 254, `${ip} out of usable range`);
  }
});

test('candidates are unique and respect the cap', () => {
  const ips = generateCandidates(CLOUDFLARE_V4, 100);
  assert.equal(new Set(ips).size, ips.length);
  assert.ok(ips.length <= 100);
});

test('candidate generation is deterministic for a fixed random source', () => {
  const fixed = () => 0.5;
  assert.deepEqual(
    generateCandidates(['104.16.0.0/24'], 5, fixed),
    generateCandidates(['104.16.0.0/24'], 5, fixed),
  );
});

test('invalid ranges produce no candidates', () => {
  assert.deepEqual(generateCandidates(['nonsense', '1.2.3.4'], 10), []);
  assert.deepEqual(generateCandidates([], 10), []);
});

test('the official list is used when reachable', async () => {
  const ranges = await fetchCloudflareRanges(async () => ({
    ok: true,
    text: async () => '1.1.1.0/24\n2.2.2.0/24',
  }), { refresh: true });
  assert.deepEqual(ranges, ['1.1.1.0/24', '2.2.2.0/24']);
});

test('a failed fetch falls back to the built-in ranges', async () => {
  const ranges = await fetchCloudflareRanges(
    async () => { throw new Error('offline'); },
    { refresh: true },
  );
  assert.ok(ranges.length >= 2);
  for (const cidr of ranges) assert.ok(isValidCidr(cidr));
});

test('a scan plan returns candidates on a TLS port', async () => {
  const plan = await buildScanPlan({
    count: 32,
    ports: [2053],
    refresh: true,   // ignore any range list cached by an earlier test
    fetchImpl: async () => ({ ok: true, text: async () => '104.16.0.0/20' }),
  });
  assert.deepEqual(plan.ports, [2053]);
  assert.ok(plan.candidates.length > 0 && plan.candidates.length <= 32);
  for (const ip of plan.candidates) assert.match(ip, /^104\.16\./);
});

test('a non-TLS port falls back to 443', async () => {
  const plan = await buildScanPlan({
    count: 8,
    ports: [80],
    refresh: true,
    fetchImpl: async () => ({ ok: true, text: async () => '104.16.0.0/24' }),
  });
  assert.deepEqual(plan.ports, [443]);
});

test('the TLS port list is the expected set', () => {
  assert.deepEqual(TLS_PORTS, [443, 2053, 2083, 2087, 2096, 8443]);
});
