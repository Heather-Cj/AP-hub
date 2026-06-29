// netlify/functions/api.mjs
// Captain Jay's AP Hub — backend (authentication + datastore)
// Stores everything in Netlify Blobs. Passwords are hashed (scrypt).
// Sessions are stateless signed tokens (HMAC). No money ever moves here —
// this only stores what your staff records.

import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const SECRET = process.env.AP_HUB_SECRET || 'PLEASE-SET-AP_HUB_SECRET-IN-NETLIFY-ENV';
const TTL = 1000 * 60 * 60 * 12; // sessions last 12 hours

// ---- Microsoft Graph / Excel sync config (all from Netlify env vars) ----
const MS = {
  tenant:   process.env.MS_TENANT_ID,        // Directory (tenant) ID
  client:   process.env.MS_CLIENT_ID,        // Application (client) ID
  secret:   process.env.MS_CLIENT_SECRET,    // client secret VALUE (not the secret ID)
  siteId:   process.env.MS_SITE_ID,          // SharePoint site id  (host,siteGuid,webGuid  OR  hostname:/sites/Name)
  driveId:  process.env.MS_DRIVE_ID || '',   // optional: specific document library drive id
  itemId:   process.env.MS_ITEM_ID || '',    // optional: workbook driveItem id (fastest, most stable)
  filePath: process.env.MS_FILE_PATH || '',  // OR path within the library, e.g. "AP/Invoices.xlsx"
  worksheet:process.env.MS_WORKSHEET || 'Sheet1',
  table:    process.env.MS_TABLE || 'Invoices', // the Excel Table name (Table Design > Table Name)
  keyCol:   process.env.MS_KEY_COLUMN || 'Invoice Id', // header of the unique match column
};
const msReady = () => MS.tenant && MS.client && MS.secret && MS.siteId && (MS.itemId || MS.filePath);

// app-only token via client-credentials
let _tok = { v: null, exp: 0 };
async function graphToken() {
  if (_tok.v && Date.now() < _tok.exp - 60000) return _tok.v;
  const r = await fetch(`https://login.microsoftonline.com/${MS.tenant}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: MS.client, client_secret: MS.secret,
      grant_type: 'client_credentials', scope: 'https://graph.microsoft.com/.default',
    }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error('token: ' + (d.error_description || JSON.stringify(d)));
  _tok = { v: d.access_token, exp: Date.now() + (d.expires_in || 3600) * 1000 };
  return _tok.v;
}
async function graph(path, opts = {}) {
  const t = await graphToken();
  const r = await fetch('https://graph.microsoft.com/v1.0' + path, {
    ...opts,
    headers: { authorization: 'Bearer ' + t, 'content-type': 'application/json', ...(opts.headers || {}) },
  });
  const text = await r.text();
  let d; try { d = text ? JSON.parse(text) : {}; } catch { d = { raw: text }; }
  if (!r.ok) { const e = new Error('graph ' + r.status + ': ' + (d.error?.message || text)); e.status = r.status; e.body = d; throw e; }
  return d;
}
// resolve the workbook driveItem base path once per call
function workbookBase() {
  if (MS.itemId) {
    return MS.driveId ? `/drives/${MS.driveId}/items/${MS.itemId}`
                      : `/sites/${MS.siteId}/drive/items/${MS.itemId}`;
  }
  const p = encodeURIComponent(MS.filePath).replace(/%2F/g, '/');
  return MS.driveId ? `/drives/${MS.driveId}/root:/${p}:`
                    : `/sites/${MS.siteId}/drive/root:/${p}:`;
}
// upsert a single row keyed by Invoice Id
async function excelUpsert(record) {
  const base = workbookBase();
  const tbl = `${base}/workbook/tables('${encodeURIComponent(MS.table)}')`;
  // 1) get the column order from the table header
  const cols = (await graph(`${tbl}/columns?$select=name,index`)).value
    .sort((a, b) => a.index - b.index).map((c) => c.name);
  const keyIdx = cols.indexOf(MS.keyCol);
  if (keyIdx < 0) throw new Error(`Key column "${MS.keyCol}" not found. Table headers: ${cols.join(', ')}`);
  const rowArr = cols.map((name) => (record[name] !== undefined && record[name] !== null) ? record[name] : '');
  const keyVal = String(record[MS.keyCol] ?? '').trim();
  if (!keyVal) throw new Error('record has no value for key column ' + MS.keyCol);

  // 2) scan existing rows for a matching key
  const rows = (await graph(`${tbl}/rows?$select=index,values`)).value;
  const hit = rows.find((row) => String((row.values?.[0] || [])[keyIdx] ?? '').trim() === keyVal);

  if (hit) {
    await graph(`${tbl}/rows/itemAt(index=${hit.index})`, {
      method: 'PATCH', body: JSON.stringify({ values: [rowArr] }),
    });
    return { updated: true, index: hit.index };
  }
  await graph(`${tbl}/rows/add`, {
    method: 'POST', body: JSON.stringify({ values: [rowArr] }),
  });
  return { added: true };
}

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });

const b64u = (s) => Buffer.from(s).toString('base64url');
const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');

function signToken(payload) {
  const body = b64u(JSON.stringify({ ...payload, exp: Date.now() + TTL }));
  return body + '.' + hmac(body);
}
function verifyToken(tok) {
  if (!tok || typeof tok !== 'string' || !tok.includes('.')) return null;
  const [body, sig] = tok.split('.');
  if (hmac(body) !== sig) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (!p.exp || Date.now() > p.exp) return null;
  return p;
}

function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 32).toString('hex');
  return salt + ':' + hash;
}
function verifyPw(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  let cand;
  try { cand = crypto.scryptSync(String(pw), salt, 32).toString('hex'); } catch { return false; }
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(cand, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const sanitize = (u) => ({ u: u.u, name: u.name, role: u.role, initials: u.initials, inTraining: !!u.inTraining, tier: u.role === 'admin' ? undefined : (Number(u.tier) || 1), perms: u.role === 'admin' ? undefined : (Array.isArray(u.perms) ? u.perms : undefined) });

// Loads users; seeds the default admin on first ever call so login works out of the box.
async function getUsers(store) {
  const v = await store.get('users', { type: 'json' });
  if (Array.isArray(v) && v.length) return v;
  const seed = [{ u: 'heather', name: 'Heather Williams', role: 'admin', initials: 'HW', pw: hashPw('captain2657') }];
  await store.setJSON('users', seed);
  return seed;
}

export default async (req) => {
  const url = new URL(req.url);
  const action = url.searchParams.get('action');
  const store = getStore('ap-hub');
  let body = {};
  if (req.method === 'POST') { try { body = await req.json(); } catch {} }

  // ---- login (public) ----
  if (action === 'login') {
    const users = await getUsers(store);
    const user = users.find((x) => x.u.toLowerCase() === String(body.u || '').toLowerCase());
    if (!user || !verifyPw(body.p, user.pw)) return json({ error: 'Incorrect username or password' }, 401);
    return json({ token: signToken({ u: user.u, role: user.role }), user: sanitize(user) });
  }

  // ---- everything below needs a valid session ----
  const tok = verifyToken(body.token || url.searchParams.get('token'));
  if (!tok) return json({ error: 'Session expired — please sign in again' }, 401);

  // ---- chunked storage helpers ----
  // Bills are sharded by month key (YYYY-MM from receivedDate) under keys "bills:<mk>".
  // A small "meta" blob holds vendors, audit, deleted, nextId, and the list of month shards.
  // The legacy single "ops" blob is still read on load (one-time migration), never written again.
  const monthKeyOf = (b) => {
    const d = String(b && b.receivedDate || '');
    const m = d.match(/^(\d{4})-(\d{2})/);
    return m ? `${m[1]}-${m[2]}` : 'undated';
  };

  if (action === 'load') {
    const users = await getUsers(store);
    const meta = await store.get('meta', { type: 'json' });
    if (meta && Array.isArray(meta.shards)) {
      // new chunked format
      let bills = [];
      for (const mk of meta.shards) {
        const chunk = await store.get('bills:' + mk, { type: 'json' });
        if (Array.isArray(chunk)) bills = bills.concat(chunk);
      }
      const ops = {
        vendors: meta.vendors || [], bills,
        audit: meta.audit || [], deleted: meta.deleted || { bills: [], vendors: [] },
        nextId: meta.nextId || 10001,
      };
      return json({ ops, users: users.map(sanitize) });
    }
    // legacy: fall back to the old single blob (gets migrated on next save)
    const ops = await store.get('ops', { type: 'json' });
    return json({ ops: ops || null, users: users.map(sanitize) });
  }

  if (action === 'saveOps') {
    const o = body.ops || {};
    const del = o.deleted && typeof o.deleted === 'object' ? o.deleted : {};
    const bills = Array.isArray(o.bills) ? o.bills : [];

    // group bills by month shard
    const groups = {};
    for (const b of bills) { const mk = monthKeyOf(b); (groups[mk] = groups[mk] || []).push(b); }
    const shards = Object.keys(groups).sort();

    // figure out which shards existed before, so we can clear ones that are now empty
    const prevMeta = await store.get('meta', { type: 'json' });
    const prevShards = (prevMeta && Array.isArray(prevMeta.shards)) ? prevMeta.shards : [];

    // write each month shard
    for (const mk of shards) await store.setJSON('bills:' + mk, groups[mk]);
    // delete shards that no longer have any bills
    for (const mk of prevShards) if (!groups[mk]) { try { await store.delete('bills:' + mk); } catch {} }

    // write the small meta blob (everything except the bills array)
    await store.setJSON('meta', {
      vendors: Array.isArray(o.vendors) ? o.vendors : [],
      audit: Array.isArray(o.audit) ? o.audit.slice(0, 800) : [],
      deleted: { bills: Array.isArray(del.bills) ? del.bills : [], vendors: Array.isArray(del.vendors) ? del.vendors : [] },
      nextId: o.nextId || 10001,
      shards,
      savedAt: Date.now(),
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
      pw: inc.password ? hashPw(inc.password) : base.pw,
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

  // ---- Microsoft Excel sync ----
  if (action === 'syncStatus') {
    return json({ configured: !!msReady(), table: MS.table, worksheet: MS.worksheet, keyCol: MS.keyCol });
  }
  if (action === 'syncInvoice') {
    if (!msReady()) return json({ error: 'Excel sync not configured (missing MS_* env vars)', configured: false }, 400);
    const rec = body.record && typeof body.record === 'object' ? body.record : null;
    if (!rec) return json({ error: 'No record provided' }, 400);
    try {
      const res = await excelUpsert(rec);
      return json({ ok: true, ...res });
    } catch (e) {
      return json({ error: String(e.message || e), status: e.status || 500 }, 200); // 200 so the UI can show a soft warning, not a hard failure
    }
  }

  return json({ error: 'Unknown action' }, 400);
};
