// Captain Jay's AP Hub — Cloudflare Worker backend
// Serves the static HTML AND handles the /api endpoint in one Worker.
// Storage: Workers KV (binding name: AP_HUB).
// Auth: stateless HMAC session tokens. Passwords hashed with PBKDF2 (Web Crypto).
// No money ever moves here — this only stores what your staff records.

const TTL = 1000 * 60 * 60 * 12; // sessions last 12 hours

// ---------- small helpers ----------
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });

const enc = new TextEncoder();
const b64u = (bytes) => {
  // bytes: Uint8Array OR string
  const arr = typeof bytes === 'string' ? enc.encode(bytes) : bytes;
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const b64uToBytes = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const hex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
const hexToBytes = (h) => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};

// ---------- HMAC session tokens (Web Crypto) ----------
async function hmacSign(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
  return b64u(sig);
}
async function signToken(secret, payload) {
  const body = b64u(JSON.stringify({ ...payload, exp: Date.now() + TTL }));
  const sig = await hmacSign(secret, body);
  return body + '.' + sig;
}
async function verifyToken(secret, tok) {
  if (!tok || typeof tok !== 'string' || !tok.includes('.')) return null;
  const [body, sig] = tok.split('.');
  const expect = await hmacSign(secret, body);
  // constant-ish time compare
  if (expect.length !== sig.length) return null;
  let diff = 0; for (let i = 0; i < expect.length; i++) diff |= expect.charCodeAt(i) ^ sig.charCodeAt(i);
  if (diff !== 0) return null;
  let p;
  try { p = JSON.parse(new TextDecoder().decode(b64uToBytes(body))); } catch { return null; }
  if (!p.exp || Date.now() > p.exp) return null;
  return p;
}

// ---------- password hashing (PBKDF2 via Web Crypto) ----------
async function pbkdf2(pw, saltBytes) {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(String(pw)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    baseKey, 256
  );
  return new Uint8Array(bits);
}
async function hashPw(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(pw, salt);
  return hex(salt) + ':' + hex(hash);
}
async function verifyPw(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [saltHex, hashHex] = stored.split(':');
  let cand;
  try { cand = await pbkdf2(pw, hexToBytes(saltHex)); } catch { return false; }
  const a = hexToBytes(hashHex);
  if (a.length !== cand.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i] ^ cand[i];
  return diff === 0;
}

const sanitize = (u) => ({ u: u.u, name: u.name, role: u.role, initials: u.initials, inTraining: !!u.inTraining, tier: u.role === 'admin' ? undefined : (Number(u.tier) || 1), perms: u.role === 'admin' ? undefined : (Array.isArray(u.perms) ? u.perms : undefined) });

// ---------- KV-backed store (mirrors the old Netlify Blobs interface) ----------
function makeStore(kv) {
  return {
    async getJSON(key) { return await kv.get(key, { type: 'json' }); },
    async setJSON(key, val) { await kv.put(key, JSON.stringify(val)); },
    async del(key) { await kv.delete(key); },
  };
}

// ---------- one-time data purge (bills only; vendors + users kept) ----------
// Bump this tag to trigger a fresh purge. Runs once, guarded by the 'purge_tag' key.
const PURGE_TAG = 'bills-wipe-2026-07-01';
async function maybePurge(store) {
  const done = await store.getJSON('purge_tag');
  if (done === PURGE_TAG) return;
  const meta = (await store.getJSON('meta')) || {};
  const shards = Array.isArray(meta.shards) ? meta.shards : [];
  // back up every bill shard + the old meta before deleting, so it's restorable
  await store.setJSON('bak:' + PURGE_TAG + ':meta', meta);
  for (const mk of shards) {
    const chunk = await store.getJSON('bills:' + mk);
    if (chunk) await store.setJSON('bak:' + PURGE_TAG + ':bills:' + mk, chunk);
    try { await store.del('bills:' + mk); } catch {}
  }
  const del = (meta.deleted && typeof meta.deleted === 'object') ? meta.deleted : {};
  const gen = Date.now();
  await store.setJSON('meta', {
    vendors: Array.isArray(meta.vendors) ? meta.vendors : [],   // keep vendors
    audit: [],
    deleted: { bills: [], vendors: Array.isArray(del.vendors) ? del.vendors : [] },
    nextId: meta.nextId || 10001,
    shards: [],
    gen,          // stamps a new generation; pre-purge sessions can no longer save
    purgedAt: gen,
  });
  try { await store.del('ops'); } catch {}   // drop the legacy single-blob store
  await store.setJSON('purge_tag', PURGE_TAG);
}

async function getUsers(store) {
  const v = await store.getJSON('users');
  if (Array.isArray(v) && v.length) return v;
  const seed = [{ u: 'heather', name: 'Heather Williams', role: 'admin', initials: 'HW', pw: await hashPw('captain2657') }];
  await store.setJSON('users', seed);
  return seed;
}

const monthKeyOf = (b) => {
  const d = String((b && b.receivedDate) || '');
  const m = d.match(/^(\d{4})-(\d{2})/);
  return m ? `${m[1]}-${m[2]}` : 'undated';
};

// ---------- Microsoft Graph / Excel sync (optional, via env vars) ----------
function msConfig(env) {
  return {
    tenant: env.MS_TENANT_ID, client: env.MS_CLIENT_ID, secret: env.MS_CLIENT_SECRET,
    siteId: env.MS_SITE_ID, driveId: env.MS_DRIVE_ID || '', itemId: env.MS_ITEM_ID || '',
    filePath: env.MS_FILE_PATH || '', worksheet: env.MS_WORKSHEET || 'Sheet1',
    table: env.MS_TABLE || 'Invoices', keyCol: env.MS_KEY_COLUMN || 'Invoice Id',
  };
}
const msReady = (MS) => MS.tenant && MS.client && MS.secret && MS.siteId && (MS.itemId || MS.filePath);
let _tok = { v: null, exp: 0 };
async function graphToken(MS) {
  if (_tok.v && Date.now() < _tok.exp - 60000) return _tok.v;
  const r = await fetch(`https://login.microsoftonline.com/${MS.tenant}/oauth2/v2.0/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: MS.client, client_secret: MS.secret, grant_type: 'client_credentials', scope: 'https://graph.microsoft.com/.default' }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error('token: ' + (d.error_description || JSON.stringify(d)));
  _tok = { v: d.access_token, exp: Date.now() + (d.expires_in || 3600) * 1000 };
  return _tok.v;
}
async function graph(MS, path, opts = {}) {
  const t = await graphToken(MS);
  const r = await fetch('https://graph.microsoft.com/v1.0' + path, { ...opts, headers: { authorization: 'Bearer ' + t, 'content-type': 'application/json', ...(opts.headers || {}) } });
  const text = await r.text();
  let d; try { d = text ? JSON.parse(text) : {}; } catch { d = { raw: text }; }
  if (!r.ok) { const e = new Error('graph ' + r.status + ': ' + (d.error?.message || text)); e.status = r.status; throw e; }
  return d;
}
function workbookBase(MS) {
  if (MS.itemId) return MS.driveId ? `/drives/${MS.driveId}/items/${MS.itemId}` : `/sites/${MS.siteId}/drive/items/${MS.itemId}`;
  const p = encodeURIComponent(MS.filePath).replace(/%2F/g, '/');
  return MS.driveId ? `/drives/${MS.driveId}/root:/${p}:` : `/sites/${MS.siteId}/drive/root:/${p}:`;
}
async function excelUpsert(MS, record) {
  const base = workbookBase(MS);
  const tbl = `${base}/workbook/tables('${encodeURIComponent(MS.table)}')`;
  const cols = (await graph(MS, `${tbl}/columns?$select=name,index`)).value.sort((a, b) => a.index - b.index).map((c) => c.name);
  const keyIdx = cols.indexOf(MS.keyCol);
  if (keyIdx < 0) throw new Error(`Key column "${MS.keyCol}" not found. Headers: ${cols.join(', ')}`);
  const rowArr = cols.map((name) => (record[name] !== undefined && record[name] !== null) ? record[name] : '');
  const keyVal = String(record[MS.keyCol] ?? '').trim();
  if (!keyVal) throw new Error('record has no value for key column ' + MS.keyCol);
  const rows = (await graph(MS, `${tbl}/rows?$select=index,values`)).value;
  const hit = rows.find((row) => String((row.values?.[0] || [])[keyIdx] ?? '').trim() === keyVal);
  if (hit) { await graph(MS, `${tbl}/rows/itemAt(index=${hit.index})`, { method: 'PATCH', body: JSON.stringify({ values: [rowArr] }) }); return { updated: true, index: hit.index }; }
  await graph(MS, `${tbl}/rows/add`, { method: 'POST', body: JSON.stringify({ values: [rowArr] }) });
  return { added: true };
}

// ---------- USPS tracking (OAuth2 client-credentials + Tracking API v3) ----------
const USPS_OAUTH_URL = 'https://apis.usps.com/oauth2/v3/token';
const USPS_TRACK_URL = 'https://apis.usps.com/tracking/v3/tracking/';
const uspsReady = (env) => !!(env.USPS_CLIENT_ID && env.USPS_CLIENT_SECRET);

// Fetch + cache an OAuth token in KV (USPS tokens last ~8h; we refresh a bit early).
async function uspsToken(env, store) {
  const cached = await store.getJSON('usps_token');
  if (cached && cached.access_token && cached.exp > Date.now() + 60_000) return cached.access_token;
  const r = await fetch(USPS_OAUTH_URL, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: env.USPS_CLIENT_ID, client_secret: env.USPS_CLIENT_SECRET }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.access_token) throw new Error('USPS auth failed (' + r.status + '): ' + JSON.stringify(d).slice(0, 200));
  await store.setJSON('usps_token', { access_token: d.access_token, exp: Date.now() + (Number(d.expires_in || 28800) * 1000) });
  return d.access_token;
}

// Raw tracking fetch for one number (also used by the diagnostic endpoint).
async function uspsTrackRaw(env, store, tn) {
  const token = await uspsToken(env, store);
  const r = await fetch(USPS_TRACK_URL + encodeURIComponent(tn) + '?expand=DETAIL', {
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
  });
  const body = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, body };
}

// Best-effort normalizer. USPS field names vary slightly by account/version, so we
// read defensively from several possible keys. Validate/tighten once we see a live
// response (the diagnostic endpoint returns the raw body for exactly this purpose).
function normalizeUsps(raw) {
  const b = raw || {};
  const events = b.trackingEvents || b.trackEvents || b.eventSummaries || (b.trackInfo && b.trackInfo.events) || [];
  const evTime = (e) => e && (e.eventTimestamp || e.eventDate || e.timestamp || e.date || '');
  const list = Array.isArray(events) ? events.slice().sort((x, y) => String(evTime(y)).localeCompare(String(evTime(x)))) : [];
  const latest = list[0] || {};
  const category = String(b.statusCategory || b.status || (latest.eventType) || '').trim();
  const summary = String(b.statusSummary || b.summary || latest.eventType || category || '').trim();
  const loc = [latest.eventCity || latest.city, latest.eventState || latest.state].filter(Boolean).join(', ') ||
              String(latest.eventLocation || latest.location || '').trim();
  const lastEventAt = evTime(latest) ? Date.parse(evTime(latest)) || null : null;
  const hay = (category + ' ' + summary + ' ' + (latest.eventType || '')).toLowerCase();
  const delivered = /deliver/.test(hay) && !/out for deliver|available|schedul/.test(hay);
  const exception = /(alert|return to sender|undeliverable|refused|no access|delivery attempt|held|exception|damage|missent|reschedul)/.test(hay);
  return {
    category, summary, location: loc, lastEventAt,
    delivered, exception,
    expectedDelivery: b.expectedDeliveryDate || b.predictedDeliveryDate || null,
    eventsCount: list.length,
  };
}

// Classify a bill's tracking state vs. thresholds; decide if a NEW alert is warranted.
function assessTracking(norm, prev, now) {
  const STUCK_MS = 24 * 60 * 60 * 1000;
  const stuck = !norm.delivered && norm.lastEventAt && (now - norm.lastEventAt) > STUCK_MS;
  const state = norm.delivered ? 'delivered' : norm.exception ? 'exception' : stuck ? 'stuck' : 'transit';
  const prevState = (prev && prev.state) || 'transit';
  // notify when we first reach delivered/exception/stuck (not on every poll)
  const notify = state !== 'transit' && state !== prevState;
  return { state, stuck, notify };
}

// Email via Resend (optional; skipped when RESEND_API_KEY / ALERT_EMAIL unset).
async function sendAlertEmail(env, subject, html) {
  if (!env.RESEND_API_KEY || !env.ALERT_EMAIL) return { skipped: true };
  const to = String(env.ALERT_EMAIL).split(',').map((s) => s.trim()).filter(Boolean);
  const from = env.ALERT_FROM || 'alerts@captainjays.net';
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({ from, to, subject, html }),
  });
  return { ok: r.ok, status: r.status };
}

// The scheduled poller: bounded batch, oldest-checked first, updates bills in place.
async function runTracking(env, store, limit = 40) {
  if (!uspsReady(env)) return { skipped: 'usps-not-configured' };
  const meta = await store.getJSON('meta');
  const shards = (meta && Array.isArray(meta.shards)) ? meta.shards : [];
  // gather in-transit checks that carry a tracking number
  const cand = []; // {mk, idx, bill}
  const shardData = {};
  for (const mk of shards) {
    const arr = await store.getJSON('bills:' + mk);
    if (!Array.isArray(arr)) continue;
    shardData[mk] = arr;
    arr.forEach((bill, idx) => {
      const tn = bill && bill.sent && bill.sent.tracking;
      if (tn && bill.checkStage !== 'delivered' && !bill.isChase) cand.push({ mk, idx, tn: String(tn).replace(/\s/g, '') });
    });
  }
  cand.sort((a, b) => {
    const ca = (shardData[a.mk][a.idx].usps && shardData[a.mk][a.idx].usps.checkedAt) || 0;
    const cb = (shardData[b.mk][b.idx].usps && shardData[b.mk][b.idx].usps.checkedAt) || 0;
    return ca - cb; // least-recently checked first
  });
  const batch = cand.slice(0, limit);
  const now = Date.now();
  const touched = new Set();
  const alerts = [];
  for (const c of batch) {
    const bill = shardData[c.mk][c.idx];
    try {
      const raw = await uspsTrackRaw(env, store, c.tn);
      if (!raw.ok) { bill.usps = { ...(bill.usps || {}), checkedAt: now, error: 'HTTP ' + raw.status }; touched.add(c.mk); continue; }
      const norm = normalizeUsps(raw.body);
      const prev = bill.usps || {};
      const { state, stuck, notify } = assessTracking(norm, prev, now);
      bill.usps = { state, stuck, category: norm.category, summary: norm.summary, location: norm.location,
        lastEventAt: norm.lastEventAt, expectedDelivery: norm.expectedDelivery, checkedAt: now, error: null };
      if (norm.delivered && bill.checkStage !== 'delivered') {
        bill.checkStage = 'delivered';
        bill.delivered = bill.delivered || { date: new Date(norm.lastEventAt || now).toISOString().slice(0, 10), initials: 'USPS' };
      }
      if (notify) alerts.push({ bill, state });
      touched.add(c.mk);
    } catch (e) {
      bill.usps = { ...(bill.usps || {}), checkedAt: now, error: String(e.message || e).slice(0, 120) };
      touched.add(c.mk);
    }
  }
  for (const mk of touched) await store.setJSON('bills:' + mk, shardData[mk]);
  if (alerts.length) {
    const rowsHtml = alerts.map((a) => {
      const b = a.bill; const label = a.state === 'delivered' ? '✅ Delivered' : a.state === 'exception' ? '⚠️ Delivery exception' : '⏳ No movement &gt;1 day';
      return `<tr><td>${label}</td><td>${b.vendor || ''}</td><td>${(b.sent && b.sent.tracking) || ''}</td><td>${(b.usps && b.usps.location) || ''}</td><td>${(b.usps && b.usps.summary) || ''}</td></tr>`;
    }).join('');
    await sendAlertEmail(env, `AP Hub · ${alerts.length} check tracking update${alerts.length !== 1 ? 's' : ''}`,
      `<p>${alerts.length} check(s) changed status:</p><table border="1" cellpadding="6" cellspacing="0"><tr><th>Status</th><th>Vendor</th><th>Tracking</th><th>Location</th><th>Detail</th></tr>${rowsHtml}</table>`);
  }
  return { candidates: cand.length, polled: batch.length, updated: touched.size, alerts: alerts.length };
}

// ---------- the API handler ----------
async function handleApi(req, env) {
  const SECRET = env.AP_HUB_SECRET || 'PLEASE-SET-AP_HUB_SECRET';
  const url = new URL(req.url);
  const action = url.searchParams.get('action');
  const store = makeStore(env.AP_HUB);
  await maybePurge(store);
  let body = {};
  if (req.method === 'POST') { try { body = await req.json(); } catch {} }

  if (action === 'login') {
    const users = await getUsers(store);
    const user = users.find((x) => x.u.toLowerCase() === String(body.u || '').toLowerCase());
    if (!user || !(await verifyPw(body.p, user.pw))) return json({ error: 'Incorrect username or password' }, 401);
    return json({ token: await signToken(SECRET, { u: user.u, role: user.role }), user: sanitize(user) });
  }

  const tok = await verifyToken(SECRET, body.token || url.searchParams.get('token'));
  if (!tok) return json({ error: 'Session expired — please sign in again' }, 401);

  if (action === 'load') {
    const users = await getUsers(store);
    const meta = await store.getJSON('meta');
    if (meta && Array.isArray(meta.shards)) {
      let bills = [];
      for (const mk of meta.shards) {
        const chunk = await store.getJSON('bills:' + mk);
        if (Array.isArray(chunk)) bills = bills.concat(chunk);
      }
      const ops = { vendors: meta.vendors || [], bills, audit: meta.audit || [], deleted: meta.deleted || { bills: [], vendors: [] }, nextId: meta.nextId || 10001 };
      return json({ ops, users: users.map(sanitize), gen: meta.gen || 0 });
    }
    const ops = await store.getJSON('ops');
    return json({ ops: ops || null, users: users.map(sanitize), gen: 0 });
  }

  if (action === 'saveOps') {
    const o = body.ops || {};
    const del = o.deleted && typeof o.deleted === 'object' ? o.deleted : {};
    const bills = Array.isArray(o.bills) ? o.bills : [];
    const groups = {};
    for (const b of bills) { const mk = monthKeyOf(b); (groups[mk] = groups[mk] || []).push(b); }
    const shards = Object.keys(groups).sort();
    const prevMeta = await store.getJSON('meta');
    const curGen = (prevMeta && prevMeta.gen) || 0;
    // concurrency guard: once a generation is stamped, a client must send the
    // matching gen to save. Pre-purge tabs (no/old gen) are rejected so they
    // cannot re-add wiped bills. Clients reload on 409 to pick up the new gen.
    if (curGen && body.gen !== curGen) return json({ error: 'Data was reset — please reload.', code: 'STALE', gen: curGen }, 409);
    const prevShards = (prevMeta && Array.isArray(prevMeta.shards)) ? prevMeta.shards : [];
    for (const mk of shards) await store.setJSON('bills:' + mk, groups[mk]);
    for (const mk of prevShards) if (!groups[mk]) { try { await store.del('bills:' + mk); } catch {} }
    await store.setJSON('meta', {
      vendors: Array.isArray(o.vendors) ? o.vendors : [],
      audit: Array.isArray(o.audit) ? o.audit.slice(0, 800) : [],
      deleted: { bills: Array.isArray(del.bills) ? del.bills : [], vendors: Array.isArray(del.vendors) ? del.vendors : [] },
      nextId: o.nextId || 10001, shards, savedAt: Date.now(), gen: curGen,
    });
    return json({ ok: true, shards: shards.length, bills: bills.length });
  }

  if (action === 'upsertUser') {
    if (tok.role !== 'admin') return json({ error: 'Admins only' }, 403);
    const users = await getUsers(store);
    const inc = body.user || {};
    const uname = String(inc.u || '').trim();
    if (!uname) return json({ error: 'Username required' }, 400);
    const i = users.findIndex((x) => x.u.toLowerCase() === uname.toLowerCase());
    const base = i >= 0 ? users[i] : {};
    const merged = {
      u: uname,
      name: inc.name ?? base.name ?? uname,
      role: inc.role ?? base.role ?? 'entry',
      initials: (inc.initials ?? base.initials ?? uname.slice(0, 2)).toUpperCase(),
      inTraining: inc.inTraining ?? base.inTraining ?? false,
      tier: (inc.role ?? base.role) === 'admin' ? undefined : (Number(inc.tier ?? base.tier) || 1),
      perms: (inc.role ?? base.role) === 'admin' ? undefined : (Array.isArray(inc.perms) ? inc.perms : (Array.isArray(base.perms) ? base.perms : undefined)),
      pw: inc.password ? await hashPw(inc.password) : base.pw,
    };
    if (!merged.pw) return json({ error: 'Password required for a new user' }, 400);
    if (i >= 0) users[i] = merged; else users.push(merged);
    await store.setJSON('users', users);
    return json({ users: users.map(sanitize) });
  }

  if (action === 'deleteUser') {
    if (tok.role !== 'admin') return json({ error: 'Admins only' }, 403);
    let users = await getUsers(store);
    const target = String(body.u || '').toLowerCase();
    users = users.filter((x) => x.u.toLowerCase() !== target);
    if (!users.some((x) => x.role === 'admin')) return json({ error: 'Cannot remove the last admin' }, 400);
    await store.setJSON('users', users);
    return json({ users: users.map(sanitize) });
  }

  const MS = msConfig(env);
  if (action === 'syncStatus') return json({ configured: !!msReady(MS), table: MS.table, worksheet: MS.worksheet, keyCol: MS.keyCol });
  if (action === 'syncInvoice') {
    if (!msReady(MS)) return json({ error: 'Excel sync not configured (missing MS_* env vars)', configured: false }, 400);
    const rec = body.record && typeof body.record === 'object' ? body.record : null;
    if (!rec) return json({ error: 'No record provided' }, 400);
    try { const res = await excelUpsert(MS, rec); return json({ ok: true, ...res }); }
    catch (e) { return json({ error: String(e.message || e), status: e.status || 500 }, 200); }
  }

  // --- USPS tracking (admin) ---
  if (action === 'uspsStatus') {
    return json({ configured: uspsReady(env), emailConfigured: !!(env.RESEND_API_KEY && env.ALERT_EMAIL) });
  }
  if (action === 'uspsDiag') {   // validate the live response shape for one tracking number
    if (tok.role !== 'admin') return json({ error: 'Admins only' }, 403);
    if (!uspsReady(env)) return json({ error: 'USPS not configured — add USPS_CLIENT_ID / USPS_CLIENT_SECRET secrets' }, 400);
    const tn = String(body.tn || '').replace(/\s/g, '');
    if (!tn) return json({ error: 'Provide a tracking number as { tn }' }, 400);
    try { const raw = await uspsTrackRaw(env, store, tn); return json({ ok: raw.ok, httpStatus: raw.status, normalized: normalizeUsps(raw.body), raw: raw.body }); }
    catch (e) { return json({ error: String(e.message || e) }, 200); }
  }
  if (action === 'trackRun') {   // run the batch poller on demand (don't wait for cron)
    if (tok.role !== 'admin') return json({ error: 'Admins only' }, 403);
    try { const res = await runTracking(env, store, Number(body.limit) || 40); return json({ ok: true, ...res }); }
    catch (e) { return json({ error: String(e.message || e) }, 200); }
  }

  return json({ error: 'Unknown action' }, 400);
}

// ---------- entry point: route /api to the handler, everything else to static assets ----------
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === '/api' || url.pathname === '/api/') {
      return handleApi(req, env);
    }
    // serve the static HTML (and any other assets) from the ASSETS binding
    const res = await env.ASSETS.fetch(req);
    // Don't let the edge/browser cache the HTML, so deploys show up immediately.
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('text/html')) {
      const h = new Headers(res.headers);
      h.set('Cache-Control', 'no-cache, no-store, must-revalidate');
      return new Response(res.body, { status: res.status, headers: h });
    }
    return res;
  },
  // Cron trigger (see wrangler.toml [triggers]): poll USPS for in-transit checks.
  async scheduled(event, env, ctx) {
    const store = makeStore(env.AP_HUB);
    ctx.waitUntil(runTracking(env, store, 40).catch((e) => console.error('tracking cron failed', e)));
  },
};
