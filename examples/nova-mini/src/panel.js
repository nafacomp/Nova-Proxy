/**
 * The admin panel: one self-contained HTML page.
 *
 * No external fonts, scripts, or images. That keeps the page fast, keeps it
 * working on a censored network, and means loading the panel never leaks a
 * request to a third party.
 */

const STYLE = `
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

const layout = (title, body) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>${STYLE}</style>
</head><body>${body}</body></html>`;

export function loginPage(error = '') {
  return layout('Sign in', `
<div class="wrap"><div class="center">
  <div class="card">
    <h2>Sign in</h2>
    <div class="msg ${error ? 'err' : ''}">${escapeHtml(error)}</div>
    <form method="POST" action="/admin/login">
      <label for="p">Password</label>
      <input id="p" name="password" type="password" required autofocus autocomplete="current-password">
      <div style="margin-top:14px"><button type="submit" style="width:100%">Sign in</button></div>
    </form>
  </div>
</div></div>`);
}

export function setupPage(error = '', claim = '') {
  // Keep ?claim= on the POST. A bare action="/admin/setup" drops it, and
  // then a configured CLAIM_TOKEN rejects the submit as a 403.
  const action = claim
    ? `/admin/setup?claim=${encodeURIComponent(claim)}`
    : '/admin/setup';
  const hidden = claim
    ? `<input type="hidden" name="claim" value="${escapeHtml(claim)}">`
    : '';
  return layout('Setup', `
<div class="wrap"><div class="center">
  <div class="card">
    <h2>Create your admin password</h2>
    <p class="muted" style="margin:0 0 14px">
      Nobody has claimed this panel yet. Set a password now, before anyone else finds it.
    </p>
    <div class="msg ${error ? 'err' : ''}">${escapeHtml(error)}</div>
    <form method="POST" action="${action}">
      ${hidden}
      <label for="p">Password (at least 10 characters)</label>
      <input id="p" name="password" type="password" required minlength="10" autofocus autocomplete="new-password">
      <div style="margin-top:14px"><button type="submit" style="width:100%">Create</button></div>
    </form>
  </div>
</div></div>`);
}

export function dashboardPage() {
  return layout('nova-mini', `
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
      <tbody id="users"><tr><td colspan="3" class="muted">Loading…</td></tr></tbody>
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
    <h2>آی‌پی تمیز (Clean IP)</h2>
    <p class="muted" style="margin:0 0 12px">
      برای هر اپراتور یک لیست آی‌پی بگذارید. پنل خودش تشخیص می‌دهد کاربر روی
      کدام اپراتور است و همان لیست را در کانفیگ می‌گذارد.
      هر خط یک <code>آی‌پی</code> یا <code>آی‌پی:پورت</code>.
    </p>

    <div id="whoami" class="muted" style="margin-bottom:12px">در حال تشخیص اپراتور شما…</div>

    <div class="field-row" style="margin-bottom:12px">
      <label style="display:flex;align-items:center;gap:8px;color:var(--tx)">
        <input type="checkbox" id="ci-on" style="width:auto" checked>
        فعال باشد
      </label>
      <div style="max-width:170px;margin-inline-start:auto">
        <label for="ci-count">چند آی‌پی در هر کانفیگ</label>
        <input id="ci-count" type="number" min="1" max="32" value="8">
      </div>
    </div>

    <div class="row">
      <div><label for="ip-mci">همراه اول (MCI)</label>
        <input id="ip-mci" placeholder="1.2.3.4، 5.6.7.8:2053"></div>
      <div><label for="ip-mtn">ایرانسل (MTN)</label>
        <input id="ip-mtn" placeholder="1.2.3.4، 5.6.7.8"></div>
    </div>
    <div class="row">
      <div><label for="ip-rightel">رایتل</label><input id="ip-rightel"></div>
      <div><label for="ip-shatel">شاتل</label><input id="ip-shatel"></div>
    </div>
    <div class="row">
      <div><label for="ip-ir">سایر اپراتورهای ایران</label><input id="ip-ir"></div>
      <div><label for="ip-all">پیش‌فرض / خارج از ایران</label><input id="ip-all"></div>
    </div>

    <div class="fg">
      <label for="ci-api">یا آدرس لیست خودتان (اختیاری)</label>
      <input id="ci-api" placeholder="https://example.com/clean-ip">
      <div class="muted" style="margin-top:6px">
        پوشه‌ای که فایل‌های <code>mci.txt</code>، <code>mtn.txt</code>،
        <code>rightel.txt</code>، <code>shatel.txt</code>، <code>ir.txt</code> و
        <code>all.txt</code> دارد. لیست دستی بالا اولویت دارد.
      </div>
    </div>

    <button onclick="saveCleanIps()">ذخیرهٔ آی‌پی‌ها</button>
  </div>

  <div class="card">
    <h2>تولید لیست برای اسکن</h2>
    <p class="muted" style="margin:0 0 12px">
      ورکر نمی‌تواند خودش آی‌پی اسکن کند (کلودفلر اتصال TCP خام به آی‌پی را
      مسدود می‌کند). ولی می‌تواند لیست کاندیدا از رنج‌های رسمی کلودفلر
      بسازد تا با یک اسکنر روی کامپیوتر خودتان تستش کنید.
    </p>
    <div class="row">
      <div><label for="sp-count">تعداد آی‌پی</label>
        <input id="sp-count" type="number" min="16" max="2048" value="512"></div>
      <div><label for="sp-port">پورت</label>
        <select id="sp-port">
          <option>443</option><option>2053</option><option>2083</option>
          <option>2087</option><option>2096</option><option>8443</option>
        </select></div>
      <div style="flex:0 0 auto;display:flex;align-items:flex-end;gap:8px">
        <button class="sec" onclick="downloadPlan()">دانلود لیست</button>
      </div>
    </div>
    <p class="muted" style="margin:0">
      بعد از اسکن، آی‌پی‌های سالم را در کادر اپراتور مربوطه بالا بچسبانید.
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
      if (el) el.value = (pools[code] || '').split('\n').filter(Boolean).join(', ');
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
    box.textContent = 'شما الان روی: ' + info.label
      + (info.org ? ' — ' + info.org : '')
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
        hosts: $('hosts').value.split(/[\n,]+/).map((h) => h.trim()).filter(Boolean),
        port: Number($('port').value),
        subName: $('subname').value.trim(),
        cleanIps,
        poolApi: $('ci-api').value.trim(),
        cleanIpEnabled: $('ci-on').checked,
        cleanIpCount: Number($('ci-count').value) || 8,
      }),
    });
    flash('آی‌پی‌های تمیز ذخیره شد');
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
    code.textContent = user.uuid.slice(0, 8) + '…';
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
    flash('Password updated, signing you out…');
    setTimeout(() => { location.href = '/admin'; }, 1200);
  } catch (err) { flash(err.message, false); }
}

load();
</script>`);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
