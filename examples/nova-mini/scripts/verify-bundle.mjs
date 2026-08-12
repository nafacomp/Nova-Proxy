// Confirms dist/worker.single.js is up to date with src/.
//
// That file is committed so it can be pasted straight into the Cloudflare
// dashboard, which means a stale copy would silently ship old code. This
// rebuilds into a temp file and compares, ignoring the generated banner.
import { execFileSync } from 'node:child_process';
import { readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const committed = join(root, 'dist/worker.single.js');
const fresh = join(tmpdir(), `nova-mini-verify-${process.pid}.js`);

execFileSync('npx', [
  'esbuild', 'src/worker.js', '--bundle', '--format=esm', '--target=es2022',
  '--external:cloudflare:sockets', `--outfile=${fresh}`,
], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] });

// Drop the banner comment; only the code itself has to match.
const strip = (text) => text.replace(/^\/\*[\s\S]*?\*\/\s*/, '').trim();

const [a, b] = await Promise.all([
  readFile(committed, 'utf8').then(strip),
  readFile(fresh, 'utf8').then(strip),
]);
await rm(fresh, { force: true });

if (a !== b) {
  console.error('✗ dist/worker.single.js is stale. Run: npm run bundle');
  process.exit(1);
}
console.log('OK: dist/worker.single.js matches src/');
