/**
 * nova-mini - a readable VLESS-over-WebSocket worker with a small admin panel.
 *
 * This is real source: every line is here, nothing is minified, and there is
 * no build step.
 *
 * Bindings (see wrangler.jsonc):
 *   KV            required. Stores users, settings, and the admin password.
 *
 * Secrets (wrangler secret put ...):
 *   CLAIM_TOKEN   recommended. Required at /admin/setup?claim=... on first run.
 *   PROXYIP       optional. host or host:port used when a direct dial fails.
 *   UUID          optional. Single-user fallback when no panel users exist.
 *
 * Files: auth.js (passwords, sessions), store.js (KV), panel.js (the UI),
 * admin.js (routes), subscription.js (client config output).
 */

import { connect } from 'cloudflare:sockets';
import { handleHttp } from './admin.js';
import { readUsers } from './store.js';

/** Cloudflare blocks outbound TCP to port 25 to stop spam relaying. */
const BLOCKED_PORTS = new Set([25]);

export default {
  async fetch(request, env, ctx) {
    try {
      // The tunnel is checked first and never touches KV before the handshake,
      // so panel traffic can never slow a connection down.
      if (request.headers.get('Upgrade') === 'websocket') {
        return handleTunnel(request, env, ctx);
      }

      if (env.KV) {
        const response = await handleHttp(request, env, new URL(request.url));
        if (response) return response;
      }

      // Anything unrecognised looks like an ordinary empty site.
      return new Response('Not found', {
        status: 404,
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      });
    } catch (error) {
      // Never leak a stack trace to a prober.
      console.error('fetch failed:', error?.message || error);
      return new Response('Bad request', { status: 400 });
    }
  },
};

async function handleTunnel(request, env, ctx) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  // A client may pack the first VLESS bytes into the handshake header to save
  // a round trip. If present, they are the start of the stream.
  const early = base64ToBytes(request.headers.get('sec-websocket-protocol') || '');

  pump(server, env, early, ctx).catch((error) => {
    console.error('tunnel closed:', error?.message || error);
    closeQuietly(server);
  });

  return new Response(null, { status: 101, webSocket: client });
}

/**
 * Collect every uuid allowed to connect: panel users first, then the UUID
 * secret as a fallback so the worker still works before any user is created.
 */
async function allowedUuids(env) {
  const uuids = new Set();
  if (env.KV) {
    try {
      for (const user of await readUsers(env)) {
        if (user?.uuid && user.enabled !== false) uuids.add(String(user.uuid).toLowerCase());
      }
    } catch (error) {
      console.error('could not read users:', error?.message || error);
    }
  }
  const fallback = String(env.UUID || '').trim().toLowerCase();
  if (fallback) uuids.add(fallback);
  return uuids;
}

/**
 * Read the VLESS header, open the upstream socket, then splice the two
 * streams together until either side closes.
 */
async function pump(ws, env, early, ctx) {
  const inbound = socketToStream(ws, early);
  const reader = inbound.getReader();

  const uuids = await allowedUuids(env);
  if (uuids.size === 0) {
    closeQuietly(ws);
    reader.releaseLock();
    throw new Error('no users configured: add one in /admin or set the UUID secret');
  }

  let header;
  try {
    header = await readVlessHeader(reader, uuids);
  } catch (error) {
    // Wrong uuid or malformed header: close without explaining why.
    closeQuietly(ws);
    reader.releaseLock();
    throw error;
  }

  const { host, port, payload, version } = header;

  if (BLOCKED_PORTS.has(port)) {
    closeQuietly(ws);
    reader.releaseLock();
    throw new Error(`port ${port} is blocked`);
  }

  // Try a direct connection first; fall back to PROXYIP only if configured.
  // Unlike upstream, there is no hidden third-party relay to fall back to.
  let socket;
  try {
    socket = await dial(host, port, payload);
  } catch (directError) {
    const proxyIp = String(env.PROXYIP || '').trim();
    if (!proxyIp) {
      closeQuietly(ws);
      reader.releaseLock();
      throw new Error(`direct dial to ${host}:${port} failed and no PROXYIP is set`);
    }
    const [proxyHost, proxyPort] = splitHostPort(proxyIp, port);
    socket = await dial(proxyHost, proxyPort, payload);
  }

  // Upstream -> client. The VLESS response header precedes the first chunk.
  let sentHeader = false;
  const toClient = socket.readable.pipeTo(
    new WritableStream({
      write(chunk) {
        if (ws.readyState !== WS_OPEN) throw new Error('client went away');
        if (sentHeader) {
          ws.send(chunk);
          return;
        }
        // new Uint8Array([version, 0]) is the 2-byte VLESS reply.
        const merged = new Uint8Array(2 + chunk.byteLength);
        merged.set([version, 0], 0);
        merged.set(new Uint8Array(chunk), 2);
        ws.send(merged);
        sentHeader = true;
      },
    }),
  );

  // Client -> upstream.
  const writer = socket.writable.getWriter();
  const toServer = (async () => {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      await writer.write(value);
    }
  })();

  const finish = Promise.allSettled([toClient, toServer]).then(() => {
    closeQuietly(ws);
    try { socket.close(); } catch { /* already closed */ }
  });

  // Keep the isolate alive until both directions drain, but never let an
  // unhandled rejection escape. An unhandled rejection here is exactly the
  // kind of thing that wedges a worker and produces error 1101.
  if (ctx?.waitUntil) ctx.waitUntil(finish.catch(() => {}));
  await finish;
}

async function dial(hostname, port, firstChunk) {
  const socket = connect({ hostname, port });
  await socket.opened;
  if (firstChunk?.byteLength) {
    const writer = socket.writable.getWriter();
    try {
      await writer.write(firstChunk);
    } finally {
      writer.releaseLock();
    }
  }
  return socket;
}

/**
 * Parse a VLESS request header.
 *
 * Layout: version(1) uuid(16) optLen(1) opt(optLen) cmd(1) port(2) type(1)
 *         address(variable) then the payload.
 * Only the TCP command (0x01) is handled; UDP is rejected.
 *
 * `allowed` is a Set of lowercase uuid strings, so several panel users can
 * share one worker. A plain string is accepted too, which keeps the tests
 * and any single-user setup working unchanged.
 */
async function readVlessHeader(reader, allowed) {
  const permitted = allowed instanceof Set ? allowed : new Set([String(allowed).toLowerCase()]);
  let buffer = new Uint8Array(0);

  // Pull from the stream until at least `need` bytes are buffered.
  const need = async (count) => {
    while (buffer.byteLength < count) {
      const { value, done } = await reader.read();
      if (done) throw new Error('stream ended inside the VLESS header');
      const next = new Uint8Array(buffer.byteLength + value.byteLength);
      next.set(buffer, 0);
      next.set(new Uint8Array(value), buffer.byteLength);
      buffer = next;
    }
    return buffer;
  };

  await need(24);
  const version = buffer[0];

  if (!permitted.has(bytesToUuid(buffer.subarray(1, 17)))) {
    throw new Error('uuid mismatch');
  }

  const optLength = buffer[17];
  let offset = 18 + optLength;

  await need(offset + 4);
  if (buffer[offset] !== 1) throw new Error('only the TCP command is supported');
  offset += 1;

  const port = (buffer[offset] << 8) | buffer[offset + 1];
  offset += 2;

  const addressType = buffer[offset];
  offset += 1;

  let host;
  if (addressType === 1) {
    await need(offset + 4);
    host = Array.from(buffer.subarray(offset, offset + 4)).join('.');
    offset += 4;
  } else if (addressType === 2) {
    await need(offset + 1);
    const length = buffer[offset];
    offset += 1;
    await need(offset + length);
    host = new TextDecoder().decode(buffer.subarray(offset, offset + length));
    offset += length;
  } else if (addressType === 3) {
    await need(offset + 16);
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buffer[offset + i] << 8) | buffer[offset + i + 1]).toString(16));
    }
    host = `[${parts.join(':')}]`;
    offset += 16;
  } else {
    throw new Error(`unknown address type ${addressType}`);
  }

  return { version, host, port, payload: buffer.subarray(offset) };
}

/** Adapt an incoming WebSocket to a ReadableStream of Uint8Array. */
function socketToStream(ws, early) {
  return new ReadableStream({
    start(controller) {
      if (early?.byteLength) controller.enqueue(early);
      ws.addEventListener('message', (event) => {
        controller.enqueue(new Uint8Array(event.data));
      });
      ws.addEventListener('close', () => {
        try { controller.close(); } catch { /* already closed */ }
      });
      // Errors are surfaced to the reader rather than thrown into the isolate.
      ws.addEventListener('error', () => {
        try { controller.error(new Error('websocket error')); } catch { /* ignore */ }
      });
    },
    cancel() {
      closeQuietly(ws);
    },
  });
}

const WS_OPEN = 1;

function closeQuietly(ws) {
  try {
    if (ws.readyState === WS_OPEN) ws.close(1000, 'done');
  } catch { /* nothing useful to do */ }
}

function splitHostPort(value, fallbackPort) {
  const text = String(value).trim();
  const match = /^\[(.+)\]:(\d+)$/.exec(text);        // [v6]:port
  if (match) return [match[1], Number(match[2])];
  if (text.startsWith('[')) return [text.replace(/[[\]]/g, ''), fallbackPort];
  const index = text.lastIndexOf(':');
  if (index > 0 && !text.slice(index + 1).includes(':')) {
    return [text.slice(0, index), Number(text.slice(index + 1)) || fallbackPort];
  }
  return [text, fallbackPort];
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

function bytesToUuid(bytes) {
  const hex = Array.from(bytes, (b) => HEX[b]).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Decode the URL-safe base64 that clients put in sec-websocket-protocol. */
function base64ToBytes(value) {
  if (!value) return null;
  try {
    const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}
