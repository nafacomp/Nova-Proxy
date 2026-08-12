// Proves analysis/worker.readable.js is the SAME PROGRAM as the deployed worker.js.
// Beautifying only moves whitespace, so the parse trees must match exactly.
// If this ever fails, do not trust the readable copy - re-generate it.
import { parse } from 'acorn';
import { readFile } from 'node:fs/promises';

const opts = { ecmaVersion: 'latest', sourceType: 'module' };

const strip = (node) => {
  if (typeof node === 'bigint') return `bigint:${node}`;
  if (Array.isArray(node)) return node.map(strip);
  if (node && typeof node === 'object') {
    const out = {};
    for (const key of Object.keys(node).sort()) {
      if (key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
      out[key] = strip(node[key]);
    }
    return out;
  }
  return node;
};

const ast = async (path) => JSON.stringify(strip(parse(await readFile(path, 'utf8'), opts)));

const [deployed, readable] = await Promise.all([
  ast(new URL('../worker.js', import.meta.url)),
  ast(new URL('../analysis/worker.readable.js', import.meta.url)),
]);

if (deployed !== readable) {
  throw new Error('analysis/worker.readable.js is NOT the same program as worker.js');
}
console.log('OK: analysis/worker.readable.js is byte-for-byte the same program as worker.js');
