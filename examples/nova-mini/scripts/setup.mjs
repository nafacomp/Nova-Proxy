#!/usr/bin/env node
/**
 * One-time setup helper for nova-mini.
 *
 * Creates the KV namespace on YOUR Cloudflare account and writes its id into
 * wrangler.jsonc, so you never have to copy a UUID by hand.
 *
 * Safe to re-run: it skips the step if the id is already filled in, and it
 * never touches secrets. Run with `npm run setup`.
 */

import { execFileSync } from 'node:child_process';
import { readFile, writeFile, copyFile } from 'node:fs/promises';

const CONFIG = new URL('../wrangler.jsonc', import.meta.url);
const WRANGLER = new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url);
const PLACEHOLDER = 'PUT-YOUR-KV-NAMESPACE-ID-HERE';
const BINDING = 'KV';

const say = (msg) => console.log(msg);
const fail = (msg) => { console.error(`\n✗ ${msg}\n`); process.exit(1); };

function wrangler(args) {
  try {
    return execFileSync(process.execPath, [WRANGLER.pathname, ...args], {
      encoding: 'utf8',
      // Capture output so we can print our own messages rather than
      // letting wrangler's raw text leak through.
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' },
    });
  } catch (error) {
    throw new Error(`${error.stdout || ''}${error.stderr || ''}`.trim() || error.message);
  }
}

/** Pull the namespace id out of wrangler's human-readable output. */
function extractId(output) {
  const explicit = output.match(/"?id"?\s*[:=]\s*"?([0-9a-f]{32})"?/i);
  if (explicit) return explicit[1];
  const loose = output.match(/\b[0-9a-f]{32}\b/i);
  return loose ? loose[0] : null;
}

say('\nnova-mini setup\n---------------');

try {
  const who = wrangler(['whoami']);
  // `whoami` exits 0 even when unauthenticated, so check the text too.
  if (/not authenticated|CLOUDFLARE_API_TOKEN|you are not logged in/i.test(who)) {
    throw new Error('not logged in');
  }
  const email = who.match(/[\w.+-]+@[\w.-]+/);
  say(`✓ Logged in to Cloudflare${email ? ` as ${email[0]}` : ''}`);
} catch {
  fail('You are not logged in to Cloudflare.\n  Run this first:  npx wrangler login');
}

let config = await readFile(CONFIG, 'utf8');

if (!config.includes(PLACEHOLDER)) {
  say('\n✓ KV id is already set, nothing to do.');
} else {
  await copyFile(CONFIG, new URL('../wrangler.jsonc.bak', import.meta.url));
  say(`\nCreating KV namespace "${BINDING}" ...`);

  let id;
  try {
    id = extractId(wrangler(['kv', 'namespace', 'create', BINDING]));
  } catch (error) {
    if (/already exists/i.test(error.message)) {
      say('  Namespace already exists, looking up its id ...');
      try {
        const list = JSON.parse(wrangler(['kv', 'namespace', 'list']));
        id = list.find((n) => n.title?.endsWith(BINDING))?.id;
      } catch { /* handled below */ }
    } else {
      fail(`Could not create the namespace:\n${error.message}`);
    }
  }

  if (!id) {
    fail(`Could not determine the namespace id. Create it manually:\n  npx wrangler kv namespace create ${BINDING}`);
  }

  await writeFile(CONFIG, config.replace(PLACEHOLDER, id));
  say(`✓ KV ready  (${id})`);
  say('✓ wrangler.jsonc updated (previous copy saved as wrangler.jsonc.bak)');
}

say(`
Next steps:

  1. Open wrangler.jsonc and change "name" to something unguessable
     (avoid vpn, proxy, nova).

  2. Set the claim token. Without it, whoever opens /admin first can
     take the panel:

       npx wrangler secret put CLAIM_TOKEN

     Generate one with:  openssl rand -hex 16

  3. Deploy:

       npm run check
       npm run deploy
`);
