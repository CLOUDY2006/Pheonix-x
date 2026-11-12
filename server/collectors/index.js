'use strict';
// PULL COLLECTORS: PHOENIX X reads your authorized logs/events itself, using a read-only API token you give it.
// No paid log-drain plan, no webhook set-up, nothing to host. Tokens are stored AES-256-GCM encrypted.
// This only READS from the platform with the user's own credentials; it does not bypass any platform control.
// Provider endpoints are written from public API docs and verified here against mock servers only, so first
// connect with a read-only token and watch "last run" on the Connect page.
const db = require('../core/db');
const audit = require('../core/audit');
const secrets = require('../core/secrets');
const normalize = require('../ingest/normalize');
const log = require('../core/log');

const BASE = {
  github: () => process.env.PHOENIX_API_GITHUB || 'https://api.github.com',
  heroku: () => process.env.PHOENIX_API_HEROKU || 'https://api.heroku.com',
  vercel: () => process.env.PHOENIX_API_VERCEL || 'https://api.vercel.com',
  render: () => process.env.PHOENIX_API_RENDER || 'https://api.render.com/v1',
  netlify: () => process.env.PHOENIX_API_NETLIFY || 'https://api.netlify.com/api/v1',
  supabase: () => process.env.PHOENIX_API_SUPABASE || 'https://api.supabase.com/v1',
};
const ID = /^[A-Za-z0-9_.-]{1,100}$/;
const SPEC = {
  github: { label: 'GitHub', fields: [{ k: 'repo', label: 'Repository (owner/name)', re: /^[\w.-]+\/[\w.-]+$/ }], scopes: 'Fine-grained token: read-only on Administration, Secret scanning alerts and Metadata for that repository.' },
  heroku: { label: 'Heroku', fields: [{ k: 'app', label: 'App name', re: ID }], scopes: 'An API token for a user or authorization with read access to the app (heroku authorizations:create --scope read-protected).' },
  vercel: { label: 'Vercel', fields: [{ k: 'teamId', label: 'Team ID (optional)', re: ID, optional: true }, { k: 'projectId', label: 'Project ID (optional)', re: ID, optional: true }], scopes: 'Account token from Settings → Tokens. Scope it to your team.' },
  render: { label: 'Render', fields: [{ k: 'serviceId', label: 'Service ID (optional, default: all services)', re: ID, optional: true }], scopes: 'API key from Account Settings → API Keys.' },
  supabase: { label: 'Supabase', fields: [{ k: 'projectRef', label: 'Project ref (optional, default: all projects)', re: ID, optional: true }], scopes: 'Personal access token from Account → Access Tokens. Used read-only to map projects and check backups; it is not a log source.' },
  netlify: { label: 'Netlify', fields: [{ k: 'siteId', label: 'Site ID', re: ID }], scopes: 'Personal access token from User settings → Applications.' },
};
const first = (...v) => v.find((x) => x !== undefined && x !== null && x !== '');
async function http(url, { token, headers = {}, method = 'GET', body, text = false } = {}) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 20000);
  try {
    const r = await fetch(url, { method, signal: ctl.signal, headers: { authorization: 'Bearer ' + token, 'user-agent': 'phoenix-x-collector', accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
    if (r.status === 401 || r.status === 403) { const e = new Error('the platform rejected the token (HTTP ' + r.status + ')'); e.auth = true; e.status = r.status; throw e; }
    if (!r.ok) { const e = new Error('HTTP ' + r.status + ' from ' + new URL(url).host); e.status = r.status; throw e; }
    return text ? await r.text() : await r.json();
  } catch (e) { if (e.name === 'AbortError') throw new Error('timed out'); throw e; } finally { clearTimeout(t); }
}
const seenOf = (cur) => new Set(cur.seen || []);
const keepSeen = (set) => [...set].slice(-800);

// Each pull(token, cfg, cursor) -> { batches: [{format, body}], cursor }. cursor.init is false on the first run (baseline: remember, don't alert).
const PULL = {
  async supabase(tok, c, cur) { await http(`${BASE.supabase()}/projects`, { token: tok }); return { batches: [], cursor: { init: true }, notes: ['Supabase is used for dependency mapping and backup checks (no log pull).'] }; },
  async github(tok, c, cur) {
    const b = BASE.github(), gh = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' }, repo = c.repo, seen = seenOf(cur), out = [], notes = [];
    const add = (id, body) => { if (!seen.has(id)) { seen.add(id); if (cur.init) out.push({ format: 'github', body }); } };
    const sender = (login) => ({ login });
    const r0 = { full_name: repo };
    try { for (const a of await http(`${b}/repos/${repo}/secret-scanning/alerts?state=open&per_page=50`, { token: tok, headers: gh })) add('sec' + a.number, { __event: 'secret_scanning_alert', action: 'created', alert: a, repository: r0 }); } catch (e) { if (e.auth && !cur.init) throw e; if (e.status === 404 || e.auth) notes.push('secret scanning not available for this token/plan'); else throw e; }
    try { for (const k of await http(`${b}/repos/${repo}/keys`, { token: tok, headers: gh })) add('key' + k.id, { __event: 'deploy_key', action: 'created', key: k, repository: r0 }); } catch (e) { if (!e.auth && e.status !== 404) throw e; notes.push('deploy keys not readable'); }
    const evs = await http(`${b}/repos/${repo}/events?per_page=50`, { token: tok, headers: gh });
    for (const e of evs) {
      if (e.type === 'PublicEvent') add('ev' + e.id, { __event: 'repository', action: 'publicized', repository: r0, sender: sender(e.actor?.login) });
      else if (e.type === 'MemberEvent' && e.payload?.action === 'added') add('ev' + e.id, { __event: 'member', action: 'added', member: e.payload.member, repository: r0, sender: sender(e.actor?.login) });
    }
    return { batches: out, cursor: { init: true, seen: keepSeen(seen) }, notes };
  },
  async heroku(tok, c, cur) {
    const b = BASE.heroku(), h = { accept: 'application/vnd.heroku+json; version=3' };
    const s = await http(`${b}/apps/${c.app}/log-sessions`, { token: tok, headers: h, method: 'POST', body: { lines: 1500, tail: false } });
    const u = new URL(s.logplex_url); if (u.origin !== new URL(b).origin && !/(^|\.)heroku\.com$/.test(u.hostname)) throw new Error('unexpected log URL host');
    const txt = await http(s.logplex_url, { token: tok, text: true, headers: { accept: 'text/plain' } });
    const last = cur.lastTs || 0; let max = last; const lines = [];
    for (const l of txt.split(/\r?\n/)) {
      const m = /^(\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:\d\d))\s+(\w+)\[([^\]]+)\]:\s?(.*)$/.exec(l); if (!m) continue; const t = Date.parse(m[1]); if (!(t > last)) continue; max = Math.max(max, t);
      lines.push(`<190>1 ${m[1]} host ${m[2]} ${m[3]} - ${m[4]}`);
    }
    return { batches: cur.init && lines.length ? [{ format: 'heroku', body: { lines: lines.join('\n') } }] : [], cursor: { init: true, lastTs: max || Date.now() }, notes: [] };
  },
  async vercel(tok, c, cur) {
    const q = new URLSearchParams({ limit: '30' }); if (c.teamId) q.set('teamId', c.teamId); if (c.projectId) q.set('projectId', c.projectId);
    const d = await http(`${BASE.vercel()}/v6/deployments?${q}`, { token: tok }); const seen = seenOf(cur), out = [];
    for (const x of d.deployments || []) {
      const st = String(x.state || x.readyState || '').toUpperCase(); if (!st || st === 'BUILDING' || st === 'QUEUED' || st === 'INITIALIZING') continue; const id = x.uid + ':' + st; if (seen.has(id)) continue; seen.add(id);
      const type = 'deployment.' + (st === 'ERROR' ? 'error' : st === 'CANCELED' ? 'canceled' : st === 'READY' ? 'succeeded' : st.toLowerCase());
      if (cur.init) out.push({ format: 'vercel-webhook', body: { id, type, createdAt: x.ready || x.created, payload: { deployment: { name: x.name }, target: x.target, user: { username: x.creator?.username || x.creator?.email } } } });
    }
    return { batches: out, cursor: { init: true, seen: keepSeen(seen) }, notes: ['Vercel request logs need a Log Drain or the SDK (no public pull API); deployments are pulled here.'] };
  },
  async netlify(tok, c, cur) {
    const d = await http(`${BASE.netlify()}/sites/${c.siteId}/deploys?per_page=20`, { token: tok }); const seen = seenOf(cur), out = [];
    for (const x of Array.isArray(d) ? d : []) { const id = x.id + ':' + x.state; if (['new', 'enqueued', 'building'].includes(x.state) || seen.has(id)) continue; seen.add(id); if (cur.init) out.push({ format: 'netlify', body: x }); }
    return { batches: out, cursor: { init: true, seen: keepSeen(seen) }, notes: [] };
  },
  async render(tok, c, cur) {
    const b = BASE.render(); let svcs = c.serviceId ? [{ id: c.serviceId }] : (await http(`${b}/services?limit=20`, { token: tok })).map((x) => x.service || x);
    const seen = seenOf(cur), out = [], notes = []; const since = cur.lastTs || Date.now() - 600e3; let max = since;
    for (const s of svcs.slice(0, 20)) {
      const name = s.name || s.id;
      try { for (const e of await http(`${b}/services/${s.id}/events?limit=20`, { token: tok })) { const ev = e.event || e; const id = ev.id; if (!id || seen.has(id)) continue; seen.add(id); if (cur.init) out.push({ format: 'render-webhook', body: { type: ev.type, timestamp: ev.timestamp, data: { id, serviceId: s.id, serviceName: name, status: first(ev.details?.status, ev.details?.reason?.failed ? 'failed' : undefined, ev.type) } } }); } } catch (e) { if (e.auth) throw e; notes.push(`events for ${name}: ${e.message}`); }
      const owner = s.ownerId || c.ownerId;
      if (owner) try {
        const q = new URLSearchParams({ ownerId: owner, startTime: new Date(since).toISOString(), limit: '200', direction: 'forward' }); q.append('resource', s.id);
        const r = await http(`${b}/logs?${q}`, { token: tok }); const lines = [];
        for (const l of r.logs || []) { const L = Object.fromEntries((l.labels || []).map((x) => [x.name, x.value])); const t = Date.parse(l.timestamp); if (t > max) max = t; if (L.type && L.type !== 'request') continue; const ip = first(L.clientIP, L.clientIp), path = first(L.path, L.url), status = first(L.statusCode, L.status); if (ip && path && status && cur.init) lines.push(`<14>1 ${l.timestamp} ${name} render - - - ${JSON.stringify({ ip, path, status, method: L.method, host: L.host })}`); }
        if (lines.length) out.push({ format: 'render', body: { lines } });
      } catch (e) { if (e.auth) throw e; notes.push('request logs: ' + e.message); }
    }
    return { batches: out, cursor: { init: true, seen: keepSeen(seen), lastTs: max === since ? Date.now() : max }, notes };
  },
};

// ---------- storage / API ----------
const row = (r) => r && ({ id: r.id, platform: r.platform, name: r.name, config: JSON.parse(r.config || '{}'), intervalSec: r.interval_sec, enabled: !!r.enabled, lastRun: r.last_run, status: r.last_status || 'pending', error: r.last_error, totalEvents: r.total_events, createdBy: r.created_by, createdAt: r.created_at, writeEnabled: !!r.write_enabled });
const list = () => db.get().prepare('select * from collectors order by created_at').all().map(row);
const TOKEN_URL = { github: 'https://github.com/settings/personal-access-tokens/new', heroku: 'https://dashboard.heroku.com/account/applications', vercel: 'https://vercel.com/account/tokens', render: 'https://dashboard.render.com/u/settings#api-keys', netlify: 'https://app.netlify.com/user/applications#personal-access-tokens' };
const catalog = () => Object.fromEntries(Object.entries(SPEC).map(([k, v]) => [k, { label: v.label, fields: v.fields.map(({ re, ...f }) => f), scopes: v.scopes, tokenUrl: TOKEN_URL[k] }]));
function cleanConfig(platform, cfg = {}) {
  const spec = SPEC[platform]; if (!spec) throw new Error('unsupported platform (github, heroku, vercel, render, netlify, supabase)'); const out = {};
  for (const f of spec.fields) { const v = String(cfg[f.k] || '').trim(); if (!v) { if (f.optional) continue; throw new Error(f.label + ' is required'); } if (!f.re.test(v)) throw new Error(f.label + ' looks invalid'); out[f.k] = v; }
  return out;
}
async function create({ platform, name, token, config, intervalSec }, by) {
  const c = cleanConfig(platform, config); if (!token || String(token).length < 8) throw new Error('API token required');
  const r = await PULL[platform](String(token).trim(), c, {}); // validates the token and baselines (no historical alerts)
  const id = 'col-' + Math.random().toString(36).slice(2, 9), iv = Math.min(3600, Math.max(30, +intervalSec || 120));
  db.get().prepare('insert into collectors(id,platform,name,token_enc,config,interval_sec,cursor,last_run,last_status,created_by,created_at) values(?,?,?,?,?,?,?,?,?,?,?)').run(id, platform, String(name || SPEC[platform].label).slice(0, 80), secrets.encrypt(String(token).trim()), JSON.stringify(c), iv, JSON.stringify(r.cursor), new Date().toISOString(), 'ok', by, new Date().toISOString());
  audit.log(by, 'COLLECTOR_ADDED', { id, platform, config: c, intervalSec: iv }); return { ...row(db.get().prepare('select * from collectors where id=?').get(id)), notes: r.notes };
}
function tokenFor(id) { const r = db.get().prepare('select * from collectors where id=?').get(id); return r ? { token: secrets.decrypt(r.token_enc), platform: r.platform, config: JSON.parse(r.config || '{}'), write: !!r.write_enabled, id: r.id, name: r.name } : null; }
function setWrite(id, on, by) { const r = db.get().prepare('update collectors set write_enabled=? where id=?').run(on ? 1 : 0, id); if (!r.changes) throw new Error('not found'); audit.log(by, on ? 'COLLECTOR_WRITE_ENABLED' : 'COLLECTOR_WRITE_DISABLED', { id }); return { ok: true, writeEnabled: !!on }; }
const running = new Set();
async function runOne(id) {
  const r = db.get().prepare('select * from collectors where id=?').get(id); if (!r || running.has(id)) return null; running.add(id);
  let status = 'ok', error = null, n = 0, cursor = JSON.parse(r.cursor || '{}'), notes = [];
  try {
    const res = await PULL[r.platform](secrets.decrypt(r.token_enc), JSON.parse(r.config), cursor); cursor = res.cursor; notes = res.notes || [];
    for (const bt of res.batches) { const o = normalize.ingest(bt.format, bt.body); n += o.accepted; }
  } catch (e) { status = e.auth ? 'auth_failed' : 'error'; error = String(e.message).slice(0, 200); log.warn?.('collector failed', { id, platform: r.platform, error }); }
  finally { running.delete(id); }
  db.get().prepare('update collectors set cursor=?, last_run=?, last_status=?, last_error=?, total_events=total_events+? where id=?').run(JSON.stringify(cursor), new Date().toISOString(), status, error, n, id);
  if (status !== 'ok' && r.last_status === 'ok') audit.log('COLLECTOR', 'COLLECTOR_FAILED', { id, platform: r.platform, error });
  return { id, status, error, events: n, notes };
}
function updateToken(id, token, by) {
  if (!token || String(token).length < 8) throw new Error('API token required'); const r = db.get().prepare('update collectors set token_enc=?, last_status=?, last_error=null where id=?').run(secrets.encrypt(String(token).trim()), 'pending', id);
  if (!r.changes) throw new Error('not found'); audit.log(by, 'COLLECTOR_TOKEN_ROTATED', { id }); return { ok: true };
}
function remove(id, by) { db.get().prepare('delete from collectors where id=?').run(id); audit.log(by, 'COLLECTOR_REMOVED', { id }); }
function setEnabled(id, on, by) { db.get().prepare('update collectors set enabled=? where id=?').run(on ? 1 : 0, id); audit.log(by, on ? 'COLLECTOR_ENABLED' : 'COLLECTOR_PAUSED', { id }); }
let timer = null;
async function tick() { const now = Date.now(); for (const c of list()) { if (!c.enabled) continue; const due = !c.lastRun || now - Date.parse(c.lastRun) >= c.intervalSec * 1000 * (c.status === 'ok' ? 1 : 3); if (due) await runOne(c.id); } }
function start(everyMs = 15000) { stop(); timer = setInterval(() => tick().catch((e) => log.error?.('collector tick', { error: e.message })), everyMs); timer.unref?.(); }
function stop() { if (timer) clearInterval(timer); timer = null; }
module.exports = { tokenFor, setWrite, BASE, http, updateToken, list, create, runOne, remove, setEnabled, tick, start, stop, catalog, cleanConfig, PULL };
