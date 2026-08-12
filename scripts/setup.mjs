#!/usr/bin/env node
/**
 * One-time setup helper.
 *
 * Creates the D1 database and KV namespace on YOUR Cloudflare account, then
 * writes their ids into wrangler.jsonc so you do not have to copy them by hand.
 *
 * Safe to re-run: it skips anything that is already filled in, and it never
 * touches secrets. Run with `npm run setup`.
 */

import { execFileSync } from 'node:child_process';
import { readFile, writeFile, copyFile } from 'node:fs/promises';

const CONFIG = new URL('../wrangler.jsonc', import.meta.url);
const DB_PLACEHOLDER = 'PUT-YOUR-D1-DATABASE-ID-HERE';
const KV_PLACEHOLDER = 'PUT-YOUR-KV-NAMESPACE-ID-HERE';
const DB_NAME = 'nova-db';
const KV_TITLE = 'KV';

const say = (msg) => console.log(msg);
const fail = (msg) => { console.error(`\n✗ ${msg}\n`); process.exit(1); };

const WRANGLER = new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url);

function wrangler(args) {
  try {
    return execFileSync(process.execPath, [WRANGLER.pathname, ...args], {
      encoding: 'utf8',
      // Capture everything so we can print our own messages instead of
      // letting wrangler's raw output leak through.
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' },
    });
  } catch (error) {
    const detail = `${error.stdout || ''}${error.stderr || ''}`.trim();
    throw new Error(detail || error.message);
  }
}

/** Pull a 32-char hex id out of wrangler's human-readable output. */
function extractId(output) {
  const explicit = output.match(/"?(?:database_id|id)"?\s*[:=]\s*"?([0-9a-f-]{32,36})"?/i);
  if (explicit) return explicit[1];
  const loose = output.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i)
    || output.match(/\b[0-9a-f]{32}\b/i);
  return loose ? loose[0] : null;
}

say('\nNova setup\n----------');

// Confirm the user is logged in before creating anything.
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
await copyFile(CONFIG, new URL('../wrangler.jsonc.bak', import.meta.url));

// ---- D1 -------------------------------------------------------------------
if (config.includes(DB_PLACEHOLDER)) {
  say(`\nCreating D1 database "${DB_NAME}" ...`);
  let id;
  try {
    id = extractId(wrangler(['d1', 'create', DB_NAME]));
  } catch (error) {
    if (/already exists/i.test(error.message)) {
      say('  Database already exists, looking up its id ...');
      try {
        const list = JSON.parse(wrangler(['d1', 'list', '--json']));
        id = list.find((d) => d.name === DB_NAME)?.uuid;
      } catch { /* fall through to the error below */ }
    } else {
      fail(`Could not create the database:\n${error.message}`);
    }
  }
  if (!id) fail(`Could not determine the database id. Create it manually:\n  npx wrangler d1 create ${DB_NAME}`);
  config = config.replace(DB_PLACEHOLDER, id);
  say(`✓ D1 ready  (${id})`);
} else {
  say('\n✓ D1 id already set, skipping');
}

// ---- KV -------------------------------------------------------------------
if (config.includes(KV_PLACEHOLDER)) {
  say(`\nCreating KV namespace "${KV_TITLE}" ...`);
  let id;
  try {
    id = extractId(wrangler(['kv', 'namespace', 'create', KV_TITLE]));
  } catch (error) {
    if (/already exists/i.test(error.message)) {
      say('  Namespace already exists, looking up its id ...');
      try {
        const list = JSON.parse(wrangler(['kv', 'namespace', 'list']));
        id = list.find((n) => n.title?.endsWith(KV_TITLE))?.id;
      } catch { /* fall through */ }
    } else {
      fail(`Could not create the namespace:\n${error.message}`);
    }
  }
  if (!id) fail(`Could not determine the namespace id. Create it manually:\n  npx wrangler kv namespace create ${KV_TITLE}`);
  config = config.replace(KV_PLACEHOLDER, id);
  say(`✓ KV ready  (${id})`);
} else {
  say('\n✓ KV id already set, skipping');
}

await writeFile(CONFIG, config);
say('\n✓ wrangler.jsonc updated (previous copy saved as wrangler.jsonc.bak)');

say(`
Next, set your secrets. The claim token matters most: without it, whoever
opens /install first can take the panel.

  npx wrangler secret put NOVA_CLAIM_TOKEN     # generate: openssl rand -hex 16
  npx wrangler secret put ADMIN                # your panel password
  npx wrangler secret put KEY                  # any long random string

Then:

  npm run check      # validate without deploying
  npm run deploy
`);
