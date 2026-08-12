# Security and verification

Nova Proxy carries traffic for people in high-censorship networks, so being able
to trust the code is part of the product. This document explains how to verify
what you run, and how to report a problem.

## Note for this private fork

This is a personal, self-hosted fork. It is not the upstream project and it does
not report to, update from, or otherwise contact the upstream maintainers.

**Important caveat about `worker.js`:** upstream `SECURITY.md` claimed that
`worker.js` is "the complete, unminified source" with "no separate build step,
bundler, or obfuscation". That claim is false. The shipped `worker.js` is a
~1.3 MB minified/bundled artifact produced by `scripts/build.mjs`, which is not
published in the repository. Treat it as a binary you cannot fully audit.

See `AUDIT.fa.md` for the full review, the list of removed callbacks, and the
verification commands.

To confirm the artifact you deploy matches the one reviewed here:

```bash
sha256sum worker.js          # compare against SHA256SUMS
node scripts/verify-release.mjs
```

## Reading worker.js

`worker.js` ships minified: names are single letters and the whole program sits on
a handful of very long lines. It is still plain JavaScript, so it can be reformatted
into something readable without changing what it does.

```bash
npm install
npm run readable      # writes analysis/worker.readable.js
```

That turns ~1,000 dense lines into ~16,000 formatted ones and annotates the
functions identified during the audit (see `analysis/rename-map.json`).

The same command then runs `scripts/verify-readable.mjs`, which parses both files
and compares their syntax trees. Formatting only moves whitespace, so the trees
must match exactly; if they ever differ the script fails and the readable copy
should not be trusted.

`analysis/` is git-ignored and never deployed. Only `worker.js` is uploaded.

**This does not recover the original source.** Minification discards the author's
variable names, comments, and file structure, and none of that can be reconstructed.
Reformatting makes the code auditable, not original. The upstream build input
(`scripts/build.mjs`) remains unpublished.

## Reporting a vulnerability

Please report security issues privately first, so users are not exposed before a
fix ships:

This is a private deployment. Open a **private security advisory** on this
repository (Security tab, "Report a vulnerability").
