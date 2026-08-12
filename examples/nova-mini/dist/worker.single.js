/* nova-mini single-file build for the Cloudflare dashboard editor. Regenerate with: npm run bundle */

// src/worker.js
import { connect } from "cloudflare:sockets";

// src/store.js
var USERS_KEY = "users.json";
var SETTINGS_KEY = "settings.json";
var ADMIN_KEY = "admin.json";
var userCache = null;
var userCacheAt = 0;
var USER_CACHE_MS = 1e4;
async function readUsers(env) {
  const now = Date.now();
  if (userCache && now - userCacheAt < USER_CACHE_MS) return userCache;
  const raw = await env.KV.get(USERS_KEY);
  userCache = safeParse(raw, []);
  userCacheAt = now;
  return userCache;
}
async function writeUsers(env, users) {
  await env.KV.put(USERS_KEY, JSON.stringify(users));
  userCache = users;
  userCacheAt = Date.now();
}
async function readSettings(env) {
  return safeParse(await env.KV.get(SETTINGS_KEY), {});
}
async function writeSettings(env, settings) {
  await env.KV.put(SETTINGS_KEY, JSON.stringify(settings));
}
async function readAdmin(env) {
  return safeParse(await env.KV.get(ADMIN_KEY), null);
}
async function writeAdmin(env, admin) {
  await env.KV.put(ADMIN_KEY, JSON.stringify(admin));
}
function safeParse(raw, fallback) {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

// src/auth.js
var ITERATIONS = 21e4;
var SESSION_MS = 12 * 60 * 60 * 1e3;
var encoder = new TextEncoder();
async function hashPassword(password, saltHex = randomHex(16)) {
  const salt = hexToBytes(saltHex);
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return { salt: saltHex, hash: bytesToHex(new Uint8Array(bits)), iterations: ITERATIONS };
}
async function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false;
  const candidate = await hashPassword(password, record.salt);
  return timingSafeEqual(candidate.hash, record.hash);
}
async function createSession(env, expiresAt = Date.now() + SESSION_MS) {
  const admin = await readAdmin(env);
  if (!admin) throw new Error("no admin configured");
  return `${expiresAt}.${await sign(env, admin.hash, String(expiresAt))}`;
}
async function verifySession(env, token) {
  if (!token || !token.includes(".")) return false;
  const [expiryText, signature] = token.split(".", 2);
  const expiresAt = Number(expiryText);
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return false;
  const admin = await readAdmin(env);
  if (!admin) return false;
  return timingSafeEqual(signature, await sign(env, admin.hash, expiryText));
}
async function isAuthenticated(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? verifySession(env, decodeURIComponent(match[1])) : false;
}
function sessionCookie(token, maxAgeSeconds = SESSION_MS / 1e3) {
  return `session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}
var clearedSessionCookie = "session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
async function setAdminPassword(env, password) {
  const record = await hashPassword(password);
  await writeAdmin(env, { ...record, updatedAt: Date.now() });
  return record;
}
async function sign(env, secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return bytesToHex(new Uint8Array(mac));
}
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function randomHex(bytes) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}
function randomUuid() {
  return crypto.randomUUID();
}
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  return Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
}

// src/panel.js
var STYLE = `
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--tx:#e6edf3;--mu:#8b949e;
--ac:#2f81f7;--ok:#3fb950;--dg:#f85149;--r:10px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px}
.wrap{max-width:920px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:20px;margin:0}
h2{font-size:15px;margin:0 0 14px}
header{display:flex;justify-content:space-between;align-items:center;
margin-bottom:22px;padding-bottom:16px;border-bottom:1px solid var(--line)}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
padding:18px;margin-bottom:16px}
label{display:block;font-size:12px;color:var(--mu);margin:0 0 5px}
input,select{width:100%;padding:9px 11px;background:var(--bg);color:var(--tx);
border:1px solid var(--line);border-radius:7px;font-size:14px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:var(--ac)}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.row>div{flex:1;min-width:150px}
button{padding:9px 15px;background:var(--ac);color:#fff;border:0;
border-radius:7px;cursor:pointer;font-size:13px;font-weight:600;font-family:inherit}
button:hover{opacity:.9}
button.sec{background:transparent;border:1px solid var(--line);color:var(--tx)}
button.dg{background:var(--dg)}
button.sm{padding:5px 10px;font-size:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:start;padding:9px 8px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--mu);font-weight:600;font-size:11px;text-transform:uppercase}
code{background:var(--bg);padding:2px 6px;border-radius:4px;
font-size:12px;font-family:ui-monospace,monospace}
.msg{padding:10px 13px;border-radius:7px;margin-bottom:14px;display:none;font-size:13px}
.msg.ok{display:block;background:rgba(63,185,80,.12);color:var(--ok)}
.msg.err{display:block;background:rgba(248,81,73,.12);color:var(--dg)}
.muted{color:var(--mu);font-size:12px}
.center{max-width:340px;margin:14vh auto}
.acts{display:flex;gap:6px;flex-wrap:wrap}
@media(max-width:600px){.hide-sm{display:none}}
`;
var layout = (title, body) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>${STYLE}</style>
</head><body>${body}</body></html>`;
function loginPage(error = "") {
  return layout("Sign in", `
<div class="wrap"><div class="center">
  <div class="card">
    <h2>Sign in</h2>
    <div class="msg ${error ? "err" : ""}">${escapeHtml(error)}</div>
    <form method="POST" action="/admin/login">
      <label for="p">Password</label>
      <input id="p" name="password" type="password" required autofocus autocomplete="current-password">
      <div style="margin-top:14px"><button type="submit" style="width:100%">Sign in</button></div>
    </form>
  </div>
</div></div>`);
}
function setupPage(error = "") {
  return layout("Setup", `
<div class="wrap"><div class="center">
  <div class="card">
    <h2>Create your admin password</h2>
    <p class="muted" style="margin:0 0 14px">
      Nobody has claimed this panel yet. Set a password now, before anyone else finds it.
    </p>
    <div class="msg ${error ? "err" : ""}">${escapeHtml(error)}</div>
    <form method="POST" action="/admin/setup">
      <label for="p">Password (at least 10 characters)</label>
      <input id="p" name="password" type="password" required minlength="10" autofocus autocomplete="new-password">
      <div style="margin-top:14px"><button type="submit" style="width:100%">Create</button></div>
    </form>
  </div>
</div></div>`);
}
function dashboardPage() {
  return layout("nova-mini", `
<div class="wrap">
  <header>
    <h1>nova-mini</h1>
    <form method="POST" action="/admin/logout"><button class="sec sm" type="submit">Sign out</button></form>
  </header>

  <div id="msg" class="msg"></div>

  <div class="card">
    <h2>Add a user</h2>
    <div class="row">
      <div><label for="n">Name</label><input id="n" placeholder="phone"></div>
      <div style="flex:0 0 auto;display:flex;align-items:flex-end">
        <button onclick="addUser()">Add</button>
      </div>
    </div>
    <p class="muted" style="margin:0">A UUID is generated for you. Each user gets their own subscription link.</p>
  </div>

  <div class="card">
    <h2>Users</h2>
    <table>
      <thead><tr><th>Name</th><th class="hide-sm">UUID</th><th>Actions</th></tr></thead>
      <tbody id="users"><tr><td colspan="3" class="muted">Loading\u2026</td></tr></tbody>
    </table>
  </div>

  <div class="card">
    <h2>Settings</h2>
    <div class="row">
      <div><label for="hosts">Hosts (one per line)</label><input id="hosts" placeholder="leave blank to use this domain"></div>
      <div><label for="port">Port</label>
        <select id="port">
          <option>443</option><option>2053</option><option>2083</option>
          <option>2087</option><option>2096</option><option>8443</option>
        </select>
      </div>
      <div><label for="subname">Subscription name</label><input id="subname" placeholder="nova-mini"></div>
    </div>
    <button onclick="saveSettings()">Save</button>
  </div>

  <div class="card">
    <h2>\u0622\u06CC\u200C\u067E\u06CC \u062A\u0645\u06CC\u0632 (Clean IP)</h2>
    <p class="muted" style="margin:0 0 12px">
      \u0628\u0631\u0627\u06CC \u0647\u0631 \u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u06CC\u06A9 \u0644\u06CC\u0633\u062A \u0622\u06CC\u200C\u067E\u06CC \u0628\u06AF\u0630\u0627\u0631\u06CC\u062F. \u067E\u0646\u0644 \u062E\u0648\u062F\u0634 \u062A\u0634\u062E\u06CC\u0635 \u0645\u06CC\u200C\u062F\u0647\u062F \u06A9\u0627\u0631\u0628\u0631 \u0631\u0648\u06CC
      \u06A9\u062F\u0627\u0645 \u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u0627\u0633\u062A \u0648 \u0647\u0645\u0627\u0646 \u0644\u06CC\u0633\u062A \u0631\u0627 \u062F\u0631 \u06A9\u0627\u0646\u0641\u06CC\u06AF \u0645\u06CC\u200C\u06AF\u0630\u0627\u0631\u062F.
      \u0647\u0631 \u062E\u0637 \u06CC\u06A9 <code>\u0622\u06CC\u200C\u067E\u06CC</code> \u06CC\u0627 <code>\u0622\u06CC\u200C\u067E\u06CC:\u067E\u0648\u0631\u062A</code>.
    </p>

    <div id="whoami" class="muted" style="margin-bottom:12px">\u062F\u0631 \u062D\u0627\u0644 \u062A\u0634\u062E\u06CC\u0635 \u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u0634\u0645\u0627\u2026</div>

    <div class="field-row" style="margin-bottom:12px">
      <label style="display:flex;align-items:center;gap:8px;color:var(--tx)">
        <input type="checkbox" id="ci-on" style="width:auto" checked>
        \u0641\u0639\u0627\u0644 \u0628\u0627\u0634\u062F
      </label>
      <div style="max-width:170px;margin-inline-start:auto">
        <label for="ci-count">\u0686\u0646\u062F \u0622\u06CC\u200C\u067E\u06CC \u062F\u0631 \u0647\u0631 \u06A9\u0627\u0646\u0641\u06CC\u06AF</label>
        <input id="ci-count" type="number" min="1" max="32" value="8">
      </div>
    </div>

    <div class="row">
      <div><label for="ip-mci">\u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644 (MCI)</label>
        <input id="ip-mci" placeholder="1.2.3.4\u060C 5.6.7.8:2053"></div>
      <div><label for="ip-mtn">\u0627\u06CC\u0631\u0627\u0646\u0633\u0644 (MTN)</label>
        <input id="ip-mtn" placeholder="1.2.3.4\u060C 5.6.7.8"></div>
    </div>
    <div class="row">
      <div><label for="ip-rightel">\u0631\u0627\u06CC\u062A\u0644</label><input id="ip-rightel"></div>
      <div><label for="ip-shatel">\u0634\u0627\u062A\u0644</label><input id="ip-shatel"></div>
    </div>
    <div class="row">
      <div><label for="ip-ir">\u0633\u0627\u06CC\u0631 \u0627\u067E\u0631\u0627\u062A\u0648\u0631\u0647\u0627\u06CC \u0627\u06CC\u0631\u0627\u0646</label><input id="ip-ir"></div>
      <div><label for="ip-all">\u067E\u06CC\u0634\u200C\u0641\u0631\u0636 / \u062E\u0627\u0631\u062C \u0627\u0632 \u0627\u06CC\u0631\u0627\u0646</label><input id="ip-all"></div>
    </div>

    <div class="fg">
      <label for="ci-api">\u06CC\u0627 \u0622\u062F\u0631\u0633 \u0644\u06CC\u0633\u062A \u062E\u0648\u062F\u062A\u0627\u0646 (\u0627\u062E\u062A\u06CC\u0627\u0631\u06CC)</label>
      <input id="ci-api" placeholder="https://example.com/clean-ip">
      <div class="muted" style="margin-top:6px">
        \u067E\u0648\u0634\u0647\u200C\u0627\u06CC \u06A9\u0647 \u0641\u0627\u06CC\u0644\u200C\u0647\u0627\u06CC <code>mci.txt</code>\u060C <code>mtn.txt</code>\u060C
        <code>rightel.txt</code>\u060C <code>shatel.txt</code>\u060C <code>ir.txt</code> \u0648
        <code>all.txt</code> \u062F\u0627\u0631\u062F. \u0644\u06CC\u0633\u062A \u062F\u0633\u062A\u06CC \u0628\u0627\u0644\u0627 \u0627\u0648\u0644\u0648\u06CC\u062A \u062F\u0627\u0631\u062F.
      </div>
    </div>

    <button onclick="saveCleanIps()">\u0630\u062E\u06CC\u0631\u0647\u0654 \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627</button>
  </div>

  <div class="card">
    <h2>\u062A\u0648\u0644\u06CC\u062F \u0644\u06CC\u0633\u062A \u0628\u0631\u0627\u06CC \u0627\u0633\u06A9\u0646</h2>
    <p class="muted" style="margin:0 0 12px">
      \u0648\u0631\u06A9\u0631 \u0646\u0645\u06CC\u200C\u062A\u0648\u0627\u0646\u062F \u062E\u0648\u062F\u0634 \u0622\u06CC\u200C\u067E\u06CC \u0627\u0633\u06A9\u0646 \u06A9\u0646\u062F (\u06A9\u0644\u0648\u062F\u0641\u0644\u0631 \u0627\u062A\u0635\u0627\u0644 TCP \u062E\u0627\u0645 \u0628\u0647 \u0622\u06CC\u200C\u067E\u06CC \u0631\u0627
      \u0645\u0633\u062F\u0648\u062F \u0645\u06CC\u200C\u06A9\u0646\u062F). \u0648\u0644\u06CC \u0645\u06CC\u200C\u062A\u0648\u0627\u0646\u062F \u0644\u06CC\u0633\u062A \u06A9\u0627\u0646\u062F\u06CC\u062F\u0627 \u0627\u0632 \u0631\u0646\u062C\u200C\u0647\u0627\u06CC \u0631\u0633\u0645\u06CC \u06A9\u0644\u0648\u062F\u0641\u0644\u0631
      \u0628\u0633\u0627\u0632\u062F \u062A\u0627 \u0628\u0627 \u06CC\u06A9 \u0627\u0633\u06A9\u0646\u0631 \u0631\u0648\u06CC \u06A9\u0627\u0645\u067E\u06CC\u0648\u062A\u0631 \u062E\u0648\u062F\u062A\u0627\u0646 \u062A\u0633\u062A\u0634 \u06A9\u0646\u06CC\u062F.
    </p>
    <div class="row">
      <div><label for="sp-count">\u062A\u0639\u062F\u0627\u062F \u0622\u06CC\u200C\u067E\u06CC</label>
        <input id="sp-count" type="number" min="16" max="2048" value="512"></div>
      <div><label for="sp-port">\u067E\u0648\u0631\u062A</label>
        <select id="sp-port">
          <option>443</option><option>2053</option><option>2083</option>
          <option>2087</option><option>2096</option><option>8443</option>
        </select></div>
      <div style="flex:0 0 auto;display:flex;align-items:flex-end;gap:8px">
        <button class="sec" onclick="downloadPlan()">\u062F\u0627\u0646\u0644\u0648\u062F \u0644\u06CC\u0633\u062A</button>
      </div>
    </div>
    <p class="muted" style="margin:0">
      \u0628\u0639\u062F \u0627\u0632 \u0627\u0633\u06A9\u0646\u060C \u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u0633\u0627\u0644\u0645 \u0631\u0627 \u062F\u0631 \u06A9\u0627\u062F\u0631 \u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u0645\u0631\u0628\u0648\u0637\u0647 \u0628\u0627\u0644\u0627 \u0628\u0686\u0633\u0628\u0627\u0646\u06CC\u062F.
    </p>
  </div>

  <div class="card">
    <h2>Change password</h2>
    <div class="row">
      <div><label for="pw">New password (at least 10 characters)</label>
        <input id="pw" type="password" autocomplete="new-password"></div>
      <div style="flex:0 0 auto;display:flex;align-items:flex-end">
        <button class="sec" onclick="changePassword()">Update</button></div>
    </div>
    <p class="muted" style="margin:0">Changing it signs out every other session.</p>
  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);

function flash(text, ok = true) {
  const el = $('msg');
  el.className = 'msg ' + (ok ? 'ok' : 'err');
  el.textContent = text;
  setTimeout(() => { el.className = 'msg'; }, 4000);
}

async function api(path, options) {
  const res = await fetch(path, { credentials: 'same-origin', ...options });
  if (res.status === 401) { location.href = '/admin'; return null; }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

const CARRIERS = ['mci', 'mtn', 'rightel', 'shatel', 'ir', 'all'];

async function load() {
  try {
    const data = await api('/admin/api/state');
    if (!data) return;
    renderUsers(data.users);
    const s = data.settings || {};
    $('hosts').value = (s.hosts || []).join(', ');
    $('port').value = s.port || 443;
    $('subname').value = s.subName || '';

    const pools = s.cleanIps || {};
    for (const code of CARRIERS) {
      const el = $('ip-' + code);
      if (el) el.value = (pools[code] || '').split('
').filter(Boolean).join(', ');
    }
    $('ci-api').value = s.poolApi || '';
    $('ci-on').checked = s.cleanIpEnabled !== false;
    $('ci-count').value = s.cleanIpCount || 8;
  } catch (err) { flash(err.message, false); }
  loadWhoami();
}

async function loadWhoami() {
  const box = $('whoami');
  try {
    const info = await api('/admin/api/whoami');
    if (!info) return;
    box.textContent = '\u0634\u0645\u0627 \u0627\u0644\u0627\u0646 \u0631\u0648\u06CC: ' + info.label
      + (info.org ? ' \u2014 ' + info.org : '')
      + (info.asn ? ' (AS' + info.asn + ')' : '');
  } catch { box.textContent = ''; }
}

async function saveCleanIps() {
  const cleanIps = {};
  for (const code of CARRIERS) {
    const el = $('ip-' + code);
    if (el && el.value.trim()) cleanIps[code] = el.value;
  }
  try {
    await api('/admin/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hosts: $('hosts').value.split(/[
,]+/).map((h) => h.trim()).filter(Boolean),
        port: Number($('port').value),
        subName: $('subname').value.trim(),
        cleanIps,
        poolApi: $('ci-api').value.trim(),
        cleanIpEnabled: $('ci-on').checked,
        cleanIpCount: Number($('ci-count').value) || 8,
      }),
    });
    flash('\u0622\u06CC\u200C\u067E\u06CC\u200C\u0647\u0627\u06CC \u062A\u0645\u06CC\u0632 \u0630\u062E\u06CC\u0631\u0647 \u0634\u062F');
    load();
  } catch (err) { flash(err.message, false); }
}

function renderUsers(users) {
  const tbody = $('users');
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="muted">No users yet.</td></tr>';
    return;
  }
  tbody.textContent = '';
  for (const user of users) {
    const tr = document.createElement('tr');

    const name = document.createElement('td');
    name.textContent = user.name;

    const uuid = document.createElement('td');
    uuid.className = 'hide-sm';
    const code = document.createElement('code');
    code.textContent = user.uuid.slice(0, 8) + '\u2026';
    uuid.appendChild(code);

    const actions = document.createElement('td');
    const box = document.createElement('div');
    box.className = 'acts';
    box.append(
      button('Copy link', 'sec sm', () => copyLink(user.token)),
      button('Delete', 'dg sm', () => removeUser(user.id, user.name)),
    );
    actions.appendChild(box);

    tr.append(name, uuid, actions);
    tbody.appendChild(tr);
  }
}

function button(label, cls, onClick) {
  const el = document.createElement('button');
  el.className = cls;
  el.textContent = label;
  el.onclick = onClick;
  return el;
}

async function copyLink(token) {
  const link = location.origin + '/sub/' + token;
  try {
    await navigator.clipboard.writeText(link);
    flash('Subscription link copied');
  } catch {
    prompt('Copy this link:', link);
  }
}

async function addUser() {
  const name = $('n').value.trim();
  if (!name) return flash('Enter a name', false);
  try {
    await api('/admin/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    $('n').value = '';
    flash('User added');
    load();
  } catch (err) { flash(err.message, false); }
}

async function removeUser(id, name) {
  if (!confirm('Delete ' + name + '? Their link stops working immediately.')) return;
  try {
    await api('/admin/api/users/' + encodeURIComponent(id), { method: 'DELETE' });
    flash('User deleted');
    load();
  } catch (err) { flash(err.message, false); }
}

async function saveSettings() {
  const hosts = $('hosts').value.split(/[\\n,]+/).map((h) => h.trim()).filter(Boolean);
  try {
    await api('/admin/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hosts,
        port: Number($('port').value),
        subName: $('subname').value.trim(),
        cleanIps: collectPools(),
        poolApi: $('ci-api').value.trim(),
        cleanIpEnabled: $('ci-on').checked,
        cleanIpCount: Number($('ci-count').value) || 8,
      }),
    });
    flash('Settings saved');
  } catch (err) { flash(err.message, false); }
}

function collectPools() {
  const out = {};
  for (const code of CARRIERS) {
    const el = $('ip-' + code);
    if (el && el.value.trim()) out[code] = el.value;
  }
  return out;
}

function downloadPlan() {
  const count = Number($('sp-count').value) || 512;
  const port = Number($('sp-port').value) || 443;
  location.href = '/admin/api/scan-plan.txt?count=' + count + '&port=' + port;
}

async function changePassword() {
  const password = $('pw').value;
  if (password.length < 10) return flash('Use at least 10 characters', false);
  try {
    await api('/admin/api/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    flash('Password updated, signing you out\u2026');
    setTimeout(() => { location.href = '/admin'; }, 1200);
  } catch (err) { flash(err.message, false); }
}

load();
<\/script>`);
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// src/subscription.js
var TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
function buildLinks(user, settings, host, cleanIps = []) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const name = settings.subName || "nova-mini";
  const primary = hosts[0] || host;
  if (cleanIps.length) {
    return cleanIps.map((entry, index) => {
      const [ip, ipPort] = splitEntry(entry, port);
      const params = new URLSearchParams({
        security: "tls",
        sni: primary,
        fp: "chrome",
        type: "ws",
        host: primary,
        path: "/",
        encryption: "none"
      });
      return `vless://${user.uuid}@${ip}:${ipPort}?${params}#${encodeURIComponent(`${name}-ip${index + 1}`)}`;
    });
  }
  return hosts.map((entry, index) => {
    const params = new URLSearchParams({
      security: "tls",
      sni: entry,
      fp: "chrome",
      type: "ws",
      host: entry,
      path: "/",
      encryption: "none"
    });
    const label = hosts.length > 1 ? `${name}-${index + 1}` : name;
    return `vless://${user.uuid}@${entry}:${port}?${params}#${encodeURIComponent(label)}`;
  });
}
function splitEntry(entry, fallbackPort) {
  const index = String(entry).lastIndexOf(":");
  if (index === -1) return [entry, fallbackPort];
  const port = Number(entry.slice(index + 1));
  return [entry.slice(0, index), port > 0 && port <= 65535 ? port : fallbackPort];
}
function toBase64(links) {
  return btoa(unescape(encodeURIComponent(links.join("\n"))));
}
function toClash(links, user, settings, host, cleanIps = []) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const primary = hosts[0] || host;
  const names = [];
  const entries = cleanIps.length ? cleanIps.map((ip, i) => {
    const [addr, addrPort] = splitEntry(ip, port);
    return { name: `nova-ip${i + 1}`, server: addr, port: addrPort, sni: primary };
  }) : hosts.map((h, i) => ({
    name: hosts.length > 1 ? `nova-${i + 1}` : "nova",
    server: h,
    port,
    sni: h
  }));
  const proxies = entries.map(({ name, server, port: p, sni }) => {
    names.push(name);
    return [
      `  - name: "${name}"`,
      "    type: vless",
      `    server: ${server}`,
      `    port: ${p}`,
      `    uuid: ${user.uuid}`,
      "    network: ws",
      "    tls: true",
      "    udp: false",
      `    servername: ${sni}`,
      "    client-fingerprint: chrome",
      "    ws-opts:",
      '      path: "/"',
      "      headers:",
      `        Host: ${sni}`
    ].join("\n");
  });
  const list = names.map((n) => `      - "${n}"`).join("\n");
  return [
    "proxies:",
    proxies.join("\n"),
    "",
    "proxy-groups:",
    '  - name: "PROXY"',
    "    type: select",
    "    proxies:",
    list,
    "",
    "rules:",
    "  - GEOIP,private,DIRECT",
    "  - MATCH,PROXY",
    ""
  ].join("\n");
}
function toSingBox(links, user, settings, host, cleanIps = []) {
  const hosts = (settings.hosts?.length ? settings.hosts : [host]).filter(Boolean);
  const port = TLS_PORTS.includes(Number(settings.port)) ? Number(settings.port) : 443;
  const primary = hosts[0] || host;
  const entries = cleanIps.length ? cleanIps.map((ip, i) => {
    const [addr, addrPort] = splitEntry(ip, port);
    return { tag: `nova-ip${i + 1}`, server: addr, port: addrPort, sni: primary };
  }) : hosts.map((h, i) => ({
    tag: hosts.length > 1 ? `nova-${i + 1}` : "nova",
    server: h,
    port,
    sni: h
  }));
  const outbounds = entries.map(({ tag, server, port: p, sni }) => ({
    type: "vless",
    tag,
    server,
    server_port: p,
    uuid: user.uuid,
    tls: { enabled: true, server_name: sni, utls: { enabled: true, fingerprint: "chrome" } },
    transport: { type: "ws", path: "/", headers: { Host: sni } }
  }));
  return JSON.stringify({
    outbounds: [
      { type: "selector", tag: "proxy", outbounds: outbounds.map((o) => o.tag) },
      ...outbounds,
      { type: "direct", tag: "direct" }
    ]
  }, null, 2);
}
function chooseFormat(url, userAgent = "") {
  const explicit = (url.searchParams.get("format") || "").toLowerCase();
  if (["base64", "clash", "singbox"].includes(explicit)) return explicit;
  const ua = userAgent.toLowerCase();
  if (/clash|mihomo|stash/.test(ua)) return "clash";
  if (/sing-?box/.test(ua)) return "singbox";
  return "base64";
}
function contentTypeFor(format) {
  if (format === "clash") return "text/yaml;charset=utf-8";
  if (format === "singbox") return "application/json;charset=utf-8";
  return "text/plain;charset=utf-8";
}

// src/cleanip.js
var CARRIERS = [
  { code: "mtn", asn: 44244, match: /irancell|mtn/ },
  { code: "mci", asn: 197207, match: /mobile communication company of iran|mcci|hamrah/ },
  { code: "rightel", asn: 57218, match: /rightel/ },
  { code: "shatel", asn: 31549, match: /shatel/ }
];
var CARRIER_CODES = ["mci", "mtn", "rightel", "shatel", "ir", "all"];
var CARRIER_LABELS = {
  mci: "\u0647\u0645\u0631\u0627\u0647 \u0627\u0648\u0644 (MCI)",
  mtn: "\u0627\u06CC\u0631\u0627\u0646\u0633\u0644 (MTN)",
  rightel: "\u0631\u0627\u06CC\u062A\u0644",
  shatel: "\u0634\u0627\u062A\u0644",
  ir: "\u0633\u0627\u06CC\u0631 \u0627\u067E\u0631\u0627\u062A\u0648\u0631\u0647\u0627\u06CC \u0627\u06CC\u0631\u0627\u0646",
  all: "\u062E\u0627\u0631\u062C \u0627\u0632 \u0627\u06CC\u0631\u0627\u0646 / \u067E\u06CC\u0634\u200C\u0641\u0631\u0636"
};
function detectCarrier(request) {
  const cf = request?.cf || {};
  if (String(cf.country || "").toUpperCase() !== "IR") return "all";
  const org = String(cf.asOrganization || "").toLowerCase();
  const asn = Number(cf.asn || 0);
  for (const carrier of CARRIERS) {
    if (asn === carrier.asn || carrier.match.test(org)) return carrier.code;
  }
  return "ir";
}
function parseIpList(text) {
  if (!text) return [];
  return String(text).split(/[\n,]+/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")).map((line) => line.split("#")[0].trim()).filter((entry) => isValidEntry(entry)).slice(0, 200);
}
function isValidEntry(entry) {
  const [host, port] = splitEntry2(entry);
  if (port !== null && !(port > 0 && port <= 65535)) return false;
  const octets = host.split(".");
  if (octets.length !== 4) return false;
  return octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}
function splitEntry2(entry) {
  const index = entry.lastIndexOf(":");
  if (index === -1) return [entry, null];
  return [entry.slice(0, index), Number(entry.slice(index + 1))];
}
var remoteCache = /* @__PURE__ */ new Map();
var REMOTE_TTL_MS = 30 * 60 * 1e3;
async function fetchRemotePool(baseUrl, carrier, fetchImpl = fetch) {
  const base = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!/^https:\/\//i.test(base)) return [];
  const candidates = [.../* @__PURE__ */ new Set([carrier, "ir", "all"])];
  for (const name of candidates) {
    const url = `${base}/${name}.txt`;
    const cached = remoteCache.get(url);
    if (cached && Date.now() - cached.at < REMOTE_TTL_MS) {
      if (cached.ips.length) return cached.ips.slice();
      continue;
    }
    try {
      const response = await fetchImpl(url, {
        headers: { "User-Agent": "nova-mini" },
        cf: { cacheTtl: 1800, cacheEverything: true }
      });
      const ips = response.ok ? parseIpList(await response.text()) : [];
      remoteCache.set(url, { at: Date.now(), ips });
      if (ips.length) return ips.slice();
    } catch {
      remoteCache.set(url, { at: Date.now(), ips: [] });
    }
  }
  return [];
}
async function resolvePool(settings, carrier, fetchImpl = fetch) {
  const pools = settings?.cleanIps || {};
  const manual = parseIpList(pools[carrier]);
  if (manual.length) return { ips: manual, source: `manual:${carrier}` };
  for (const fallback of ["ir", "all"]) {
    const list = parseIpList(pools[fallback]);
    if (list.length) return { ips: list, source: `manual:${fallback}` };
  }
  if (settings?.poolApi) {
    const remote = await fetchRemotePool(settings.poolApi, carrier, fetchImpl);
    if (remote.length) return { ips: remote, source: `remote:${carrier}` };
  }
  return { ips: [], source: "none" };
}
function pickIps(ips, limit = 8, seed = Date.now()) {
  if (ips.length <= limit) return ips.slice();
  const start = Math.abs(Math.floor(seed)) % ips.length;
  const out = [];
  for (let i = 0; i < limit; i += 1) out.push(ips[(start + i) % ips.length]);
  return out;
}

// src/cidr.js
var CLOUDFLARE_V4 = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22"
];
var TLS_PORTS2 = [443, 2053, 2083, 2087, 2096, 8443];
var OFFICIAL_V4_URL = "https://www.cloudflare.com/ips-v4";
var cache = null;
var cachedAt = 0;
var CACHE_MS = 24 * 60 * 60 * 1e3;
async function fetchCloudflareRanges(fetchImpl = fetch, { refresh = false } = {}) {
  const now = Date.now();
  if (!refresh && cache && now - cachedAt < CACHE_MS) return cache.slice();
  try {
    const response = await fetchImpl(OFFICIAL_V4_URL, {
      cf: { cacheTtl: 86400, cacheEverything: true }
    });
    if (response.ok) {
      const ranges = parseCidrList(await response.text());
      if (ranges.length) {
        cache = ranges;
        cachedAt = now;
        return ranges.slice();
      }
    }
  } catch {
  }
  cache = CLOUDFLARE_V4.slice();
  cachedAt = now;
  return cache.slice();
}
function parseCidrList(text) {
  return String(text || "").split(/[\s,]+/).map((line) => line.trim()).filter((line) => isValidCidr(line));
}
function isValidCidr(value) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(String(value));
  if (!match) return false;
  const bits = Number(match[5]);
  if (bits < 0 || bits > 32) return false;
  return match.slice(1, 5).every((octet) => Number(octet) <= 255);
}
function ipToInt(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8 >>> 0) + Number(octet), 0) >>> 0;
}
function intToIp(value) {
  const n = value >>> 0;
  return [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255].join(".");
}
function cidrRange(cidr) {
  const [base, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  const start = ipToInt(base) & (bits === 0 ? 0 : ~0 << 32 - bits >>> 0);
  const size = bits >= 31 ? 2 ** (32 - bits) : 2 ** (32 - bits) - 2;
  const first = bits >= 31 ? start : start + 1;
  return [first >>> 0, first + Math.max(0, size - 1) >>> 0];
}
function generateCandidates(cidrs, count = 512, random = Math.random) {
  const valid = cidrs.filter(isValidCidr);
  if (!valid.length) return [];
  const limit = Math.max(1, Math.min(4096, Math.floor(count)));
  const perRange = Math.max(1, Math.ceil(limit / valid.length));
  const seen = /* @__PURE__ */ new Set();
  for (const cidr of valid) {
    const [first, last] = cidrRange(cidr);
    const span = last - first + 1;
    if (span <= 0) continue;
    for (let i = 0; i < perRange && seen.size < limit; i += 1) {
      seen.add(intToIp(first + Math.floor(random() * span) >>> 0));
    }
    if (seen.size >= limit) break;
  }
  return [...seen];
}
async function buildScanPlan({
  count = 512,
  ports = [443],
  fetchImpl = fetch,
  refresh = false
} = {}) {
  const ranges = await fetchCloudflareRanges(fetchImpl, { refresh });
  const chosen = ports.filter((port) => TLS_PORTS2.includes(Number(port)));
  return {
    generatedAt: Date.now(),
    ranges: ranges.length,
    ports: chosen.length ? chosen : [443],
    candidates: generateCandidates(ranges, count)
  };
}

// src/admin.js
var json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "Content-Type": "application/json;charset=utf-8", "Cache-Control": "no-store" }
});
var html = (body, status = 200, headers = {}) => new Response(body, {
  status,
  headers: {
    "Content-Type": "text/html;charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    // The panel's only inline script is our own; nothing loads from outside.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'",
    ...headers
  }
});
function hashSeed(text) {
  let hash = 0;
  for (let i = 0; i < String(text).length; i += 1) {
    hash = hash * 31 + String(text).charCodeAt(i) >>> 0;
  }
  return hash;
}
var attempts = /* @__PURE__ */ new Map();
var MAX_ATTEMPTS = 6;
var WINDOW_MS = 10 * 60 * 1e3;
function throttled(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || now - entry.first > WINDOW_MS) return false;
  return entry.count >= MAX_ATTEMPTS;
}
function noteFailure(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || now - entry.first > WINDOW_MS) attempts.set(ip, { count: 1, first: now });
  else entry.count += 1;
  if (attempts.size > 1e3) {
    for (const [key, value] of attempts) {
      if (now - value.first > WINDOW_MS) attempts.delete(key);
      if (attempts.size <= 500) break;
    }
  }
}
function clearFailures(request) {
  attempts.delete(request.headers.get("CF-Connecting-IP") || "unknown");
}
async function handleHttp(request, env, url) {
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (path === "/sub" || path.startsWith("/sub/")) return handleSubscription(request, env, url, path);
  if (path === "/admin" || path.startsWith("/admin/")) return handleAdmin(request, env, url, path);
  return null;
}
async function handleSubscription(request, env, url, path) {
  const token = path.startsWith("/sub/") ? path.slice(5) : url.searchParams.get("token") || "";
  if (!token) return new Response("Not found", { status: 404 });
  const users = await readUsers(env);
  const user = users.find((candidate) => timingSafeEqual(candidate.token, token));
  if (!user || user.enabled === false) return new Response("Not found", { status: 404 });
  const settings = await readSettings(env);
  const carrier = String(url.searchParams.get("carrier") || "").toLowerCase();
  const detected = CARRIER_CODES.includes(carrier) ? carrier : detectCarrier(request);
  let cleanIps = [];
  if (settings.cleanIpEnabled !== false) {
    const pool = await resolvePool(settings, detected);
    cleanIps = pickIps(pool.ips, Number(settings.cleanIpCount) || 8, hashSeed(user.token));
  }
  const links = buildLinks(user, settings, url.hostname, cleanIps);
  const format = chooseFormat(url, request.headers.get("User-Agent") || "");
  const body = format === "clash" ? toClash(links, user, settings, url.hostname, cleanIps) : format === "singbox" ? toSingBox(links, user, settings, url.hostname, cleanIps) : toBase64(links);
  return new Response(body, {
    headers: {
      "Content-Type": contentTypeFor(format),
      "Cache-Control": "no-store",
      "Profile-Update-Interval": "12",
      "X-Nova-Carrier": detected,
      "Subscription-Userinfo": "upload=0; download=0; total=0",
      "Content-Disposition": `attachment; filename="${settings.subName || "nova-mini"}"`
    }
  });
}
async function handleAdmin(request, env, url, path) {
  const admin = await readAdmin(env);
  if (!admin) {
    if (path === "/admin/setup" && request.method === "POST") {
      const claim = String(env.CLAIM_TOKEN || "");
      if (claim && !timingSafeEqual(url.searchParams.get("claim") || "", claim)) {
        return html(setupPage("Add ?claim=<your CLAIM_TOKEN> to this URL."), 403);
      }
      const form = await request.formData();
      const password = String(form.get("password") || "");
      if (password.length < 10) return html(setupPage("Use at least 10 characters."), 400);
      await setAdminPassword(env, password);
      return new Response(null, {
        status: 303,
        headers: { Location: "/admin", "Set-Cookie": sessionCookie(await createSession(env)) }
      });
    }
    return html(setupPage());
  }
  if (path === "/admin/login" && request.method === "POST") {
    if (throttled(request)) return html(loginPage("Too many attempts. Wait a few minutes."), 429);
    const form = await request.formData();
    if (!await verifyPassword(String(form.get("password") || ""), admin)) {
      noteFailure(request);
      return html(loginPage("Wrong password."), 401);
    }
    clearFailures(request);
    return new Response(null, {
      status: 303,
      headers: { Location: "/admin", "Set-Cookie": sessionCookie(await createSession(env)) }
    });
  }
  if (path === "/admin/logout" && request.method === "POST") {
    return new Response(null, { status: 303, headers: { Location: "/admin", "Set-Cookie": clearedSessionCookie } });
  }
  const signedIn = await isAuthenticated(request, env);
  if (!signedIn) {
    if (path.startsWith("/admin/api/")) return json({ error: "unauthorized" }, 401);
    return html(loginPage());
  }
  if (path === "/admin") return html(dashboardPage());
  if (path.startsWith("/admin/api/")) return handleApi(request, env, path);
  return new Response("Not found", { status: 404 });
}
async function handleApi(request, env, path) {
  if (request.method !== "GET") {
    const origin = request.headers.get("Origin");
    if (origin && new URL(origin).origin !== new URL(request.url).origin) {
      return json({ error: "cross-origin request rejected" }, 403);
    }
  }
  if (path === "/admin/api/whoami" && request.method === "GET") {
    const cf = request.cf || {};
    const carrier = detectCarrier(request);
    return json({
      carrier,
      label: CARRIER_LABELS[carrier] || carrier,
      country: cf.country || null,
      asn: cf.asn || null,
      org: cf.asOrganization || null
    });
  }
  if (path === "/admin/api/scan-plan" && request.method === "GET") {
    const url = new URL(request.url);
    const count = Math.max(16, Math.min(2048, Number(url.searchParams.get("count")) || 512));
    const port = Number(url.searchParams.get("port")) || 443;
    const plan = await buildScanPlan({
      count,
      ports: [TLS_PORTS2.includes(port) ? port : 443]
    });
    return json(plan);
  }
  if (path === "/admin/api/scan-plan.txt" && request.method === "GET") {
    const url = new URL(request.url);
    const count = Math.max(16, Math.min(2048, Number(url.searchParams.get("count")) || 512));
    const port = Number(url.searchParams.get("port")) || 443;
    const chosen = TLS_PORTS2.includes(port) ? port : 443;
    const plan = await buildScanPlan({ count, ports: [chosen] });
    return new Response(plan.candidates.map((ip) => `${ip}:${chosen}`).join("\n") + "\n", {
      headers: {
        "Content-Type": "text/plain;charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Disposition": 'attachment; filename="scan-candidates.txt"'
      }
    });
  }
  if (path === "/admin/api/state" && request.method === "GET") {
    const [users, settings] = await Promise.all([readUsers(env), readSettings(env)]);
    return json({ users, settings });
  }
  if (path === "/admin/api/users" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const name = String(body.name || "").trim().slice(0, 40);
    if (!name) return json({ error: "name is required" }, 400);
    const users = await readUsers(env);
    const max = Number(env.MAX_USERS) || 10;
    if (users.length >= max) return json({ error: `user limit of ${max} reached` }, 400);
    users.push({
      id: randomHex(8),
      name,
      uuid: randomUuid(),
      token: randomHex(16),
      enabled: true,
      createdAt: Date.now()
    });
    await writeUsers(env, users);
    return json({ ok: true });
  }
  const deleteMatch = path.match(/^\/admin\/api\/users\/([\w-]+)$/);
  if (deleteMatch && request.method === "DELETE") {
    const users = await readUsers(env);
    const remaining = users.filter((user) => user.id !== deleteMatch[1]);
    if (remaining.length === users.length) return json({ error: "user not found" }, 404);
    await writeUsers(env, remaining);
    return json({ ok: true });
  }
  if (path === "/admin/api/settings" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const hosts = Array.isArray(body.hosts) ? body.hosts.map((h) => String(h).trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0]).filter(Boolean).slice(0, 10) : [];
    const cleanIps = {};
    if (body.cleanIps && typeof body.cleanIps === "object") {
      for (const code of CARRIER_CODES) {
        const parsed = parseIpList(body.cleanIps[code]);
        if (parsed.length) cleanIps[code] = parsed.join("\n");
      }
    }
    const poolApi = String(body.poolApi || "").trim();
    if (poolApi && !/^https:\/\//i.test(poolApi)) {
      return json({ error: "the pool URL must start with https://" }, 400);
    }
    await writeSettings(env, {
      hosts,
      port: Number(body.port) || 443,
      subName: String(body.subName || "").trim().slice(0, 40),
      cleanIps,
      poolApi,
      cleanIpEnabled: body.cleanIpEnabled !== false,
      cleanIpCount: Math.max(1, Math.min(32, Number(body.cleanIpCount) || 8))
    });
    return json({ ok: true });
  }
  if (path === "/admin/api/password" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const password = String(body.password || "");
    if (password.length < 10) return json({ error: "use at least 10 characters" }, 400);
    await setAdminPassword(env, password);
    return json({ ok: true });
  }
  return json({ error: "not found" }, 404);
}

// src/worker.js
var BLOCKED_PORTS = /* @__PURE__ */ new Set([25]);
var worker_default = {
  async fetch(request, env, ctx) {
    try {
      if (request.headers.get("Upgrade") === "websocket") {
        return handleTunnel(request, env, ctx);
      }
      if (env.KV) {
        const response = await handleHttp(request, env, new URL(request.url));
        if (response) return response;
      }
      return new Response("Not found", {
        status: 404,
        headers: { "Content-Type": "text/plain;charset=utf-8" }
      });
    } catch (error) {
      console.error("fetch failed:", error?.message || error);
      return new Response("Bad request", { status: 400 });
    }
  }
};
async function handleTunnel(request, env, ctx) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();
  const early = base64ToBytes(request.headers.get("sec-websocket-protocol") || "");
  pump(server, env, early, ctx).catch((error) => {
    console.error("tunnel closed:", error?.message || error);
    closeQuietly(server);
  });
  return new Response(null, { status: 101, webSocket: client });
}
async function allowedUuids(env) {
  const uuids = /* @__PURE__ */ new Set();
  if (env.KV) {
    try {
      for (const user of await readUsers(env)) {
        if (user?.uuid && user.enabled !== false) uuids.add(String(user.uuid).toLowerCase());
      }
    } catch (error) {
      console.error("could not read users:", error?.message || error);
    }
  }
  const fallback = String(env.UUID || "").trim().toLowerCase();
  if (fallback) uuids.add(fallback);
  return uuids;
}
async function pump(ws, env, early, ctx) {
  const inbound = socketToStream(ws, early);
  const reader = inbound.getReader();
  const uuids = await allowedUuids(env);
  if (uuids.size === 0) {
    closeQuietly(ws);
    reader.releaseLock();
    throw new Error("no users configured: add one in /admin or set the UUID secret");
  }
  let header;
  try {
    header = await readVlessHeader(reader, uuids);
  } catch (error) {
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
  let socket;
  try {
    socket = await dial(host, port, payload);
  } catch (directError) {
    const proxyIp = String(env.PROXYIP || "").trim();
    if (!proxyIp) {
      closeQuietly(ws);
      reader.releaseLock();
      throw new Error(`direct dial to ${host}:${port} failed and no PROXYIP is set`);
    }
    const [proxyHost, proxyPort] = splitHostPort(proxyIp, port);
    socket = await dial(proxyHost, proxyPort, payload);
  }
  let sentHeader = false;
  const toClient = socket.readable.pipeTo(
    new WritableStream({
      write(chunk) {
        if (ws.readyState !== WS_OPEN) throw new Error("client went away");
        if (sentHeader) {
          ws.send(chunk);
          return;
        }
        const merged = new Uint8Array(2 + chunk.byteLength);
        merged.set([version, 0], 0);
        merged.set(new Uint8Array(chunk), 2);
        ws.send(merged);
        sentHeader = true;
      }
    })
  );
  const writer = socket.writable.getWriter();
  const toServer = (async () => {
    for (; ; ) {
      const { value, done } = await reader.read();
      if (done) break;
      await writer.write(value);
    }
  })();
  const finish = Promise.allSettled([toClient, toServer]).then(() => {
    closeQuietly(ws);
    try {
      socket.close();
    } catch {
    }
  });
  if (ctx?.waitUntil) ctx.waitUntil(finish.catch(() => {
  }));
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
async function readVlessHeader(reader, allowed) {
  const permitted = allowed instanceof Set ? allowed : /* @__PURE__ */ new Set([String(allowed).toLowerCase()]);
  let buffer = new Uint8Array(0);
  const need = async (count) => {
    while (buffer.byteLength < count) {
      const { value, done } = await reader.read();
      if (done) throw new Error("stream ended inside the VLESS header");
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
    throw new Error("uuid mismatch");
  }
  const optLength = buffer[17];
  let offset = 18 + optLength;
  await need(offset + 4);
  if (buffer[offset] !== 1) throw new Error("only the TCP command is supported");
  offset += 1;
  const port = buffer[offset] << 8 | buffer[offset + 1];
  offset += 2;
  const addressType = buffer[offset];
  offset += 1;
  let host;
  if (addressType === 1) {
    await need(offset + 4);
    host = Array.from(buffer.subarray(offset, offset + 4)).join(".");
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
      parts.push((buffer[offset + i] << 8 | buffer[offset + i + 1]).toString(16));
    }
    host = `[${parts.join(":")}]`;
    offset += 16;
  } else {
    throw new Error(`unknown address type ${addressType}`);
  }
  return { version, host, port, payload: buffer.subarray(offset) };
}
function socketToStream(ws, early) {
  return new ReadableStream({
    start(controller) {
      if (early?.byteLength) controller.enqueue(early);
      ws.addEventListener("message", (event) => {
        controller.enqueue(new Uint8Array(event.data));
      });
      ws.addEventListener("close", () => {
        try {
          controller.close();
        } catch {
        }
      });
      ws.addEventListener("error", () => {
        try {
          controller.error(new Error("websocket error"));
        } catch {
        }
      });
    },
    cancel() {
      closeQuietly(ws);
    }
  });
}
var WS_OPEN = 1;
function closeQuietly(ws) {
  try {
    if (ws.readyState === WS_OPEN) ws.close(1e3, "done");
  } catch {
  }
}
function splitHostPort(value, fallbackPort) {
  const text = String(value).trim();
  const match = /^\[(.+)\]:(\d+)$/.exec(text);
  if (match) return [match[1], Number(match[2])];
  if (text.startsWith("[")) return [text.replace(/[[\]]/g, ""), fallbackPort];
  const index = text.lastIndexOf(":");
  if (index > 0 && !text.slice(index + 1).includes(":")) {
    return [text.slice(0, index), Number(text.slice(index + 1)) || fallbackPort];
  }
  return [text, fallbackPort];
}
var HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToUuid(bytes) {
  const hex = Array.from(bytes, (b) => HEX[b]).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
function base64ToBytes(value) {
  if (!value) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}
export {
  worker_default as default
};
