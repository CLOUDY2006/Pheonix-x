'use strict';
// Boots the REAL server in production mode as a child process (config is read at require time) and drives it over HTTP.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs'); const os = require('os'); const path = require('path');
const PORT = 4300 + Math.floor(Math.random() * 500), base = 'http://127.0.0.1:' + PORT;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phx-prod-')), DB = path.join(dir, 'p.db');
let child, out = '';
const env = { ...process.env, PHOENIX_MODE: 'production', PORT: String(PORT), HOST: '127.0.0.1', PHOENIX_DB: DB, PHOENIX_SETUP_TOKEN: 'setup-secret-1', PHOENIX_CORRELATE_MS: '600', PHOENIX_APPROVAL_TIMEOUT_MIN: '30', PHOENIX_QUIET: '' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const start = async () => { child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, '..', 'server', 'index.js')], { env }); child.stdout.on('data', (d) => (out += d)); child.stderr.on('data', (d) => (out += d)); for (let i = 0; i < 80; i++) { try { if ((await fetch(base + '/healthz')).ok) return; } catch { /* not up */ } await sleep(100); } throw new Error('server did not start: ' + out); };
const stop = () => new Promise((r) => { if (!child || child.exitCode !== null) return r(); child.on('exit', r); child.kill('SIGTERM'); });
async function call(method, p, { body, s, headers = {} } = {}) { const r = await fetch(base + p, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(s ? { cookie: s.cookie, 'x-csrf-token': s.csrf } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined }); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; } return { status: r.status, body: j, headers: r.headers }; }
const until = async (fn, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = await fn(); if (v) return v; await sleep(150); } throw new Error('timeout'); };
test.before(start); test.after(stop);

let admin;
test('first run requires the setup token; demo accounts do not exist', async () => {
  assert.equal((await call('GET', '/api/auth/status')).body.setupRequired, true);
  assert.equal((await call('POST', '/api/auth/login', { body: { username: 'admin', password: 'phoenix-demo' } })).status, 401);
  assert.equal((await call('POST', '/api/auth/setup', { body: { username: 'root', password: 'long-enough-pass-1', setupToken: 'wrong' } })).status, 400);
  assert.equal((await call('POST', '/api/auth/setup', { body: { username: 'root', password: 'weak', setupToken: 'setup-secret-1' } })).status, 400);
  const r = await call('POST', '/api/auth/setup', { body: { username: 'root', password: 'long-enough-pass-1', setupToken: 'setup-secret-1' } }); assert.equal(r.status, 200);
  admin = { cookie: r.headers.get('set-cookie').split(';')[0], csrf: r.body.csrf }; assert.match(r.headers.get('set-cookie'), /Secure/, 'cookies are Secure in production');
  assert.equal((await call('POST', '/api/auth/setup', { body: { username: 'r2', password: 'long-enough-pass-1', setupToken: 'setup-secret-1' } })).status, 409, 'setup is one-shot');
});
test('production starts EMPTY: no simulated assets, no generator, no demo scenarios', async () => {
  const st = (await call('GET', '/api/state', { s: admin })).body;
  assert.equal(st.mode, 'production'); assert.equal(st.incidents.length, 0); assert.equal(Object.keys(st.assets.users || {}).length + Object.keys(st.assets.hosts || {}).length, 0);
  assert.equal(st.settings.generator, false); assert.equal(st.settings.autoContain, false);
  assert.equal((await call('POST', '/api/scenarios/signature/launch', { s: admin, body: {} })).status, 403);
  assert.equal((await call('POST', '/api/reset', { s: admin, body: {} })).status, 403);
  assert.equal((await call('POST', '/api/settings', { s: admin, body: { autopilot: true } })).status, 403);
});
let key;
test('real events -> incident -> every containment action waits for a human; nothing auto-runs', async () => {
  key = (await call('POST', '/api/keys', { s: admin, body: { name: 'idp', format: 'generic' } })).body.key;
  const t0 = Date.now(), ip = '198.51.100.77', evs = [];
  for (let i = 0; i < 14; i++) evs.push({ source: 'authentication', type: 'login_failed', user: 'victim@corp.example', ip, outcome: 'failure', ts: new Date(t0 - (14 - i) * 1000).toISOString(), geo: { country: 'Romania', city: 'Bucharest' } });
  evs.push({ source: 'authentication', type: 'login_success', user: 'victim@corp.example', ip, outcome: 'success', ts: new Date(t0).toISOString(), geo: { country: 'Romania', city: 'Bucharest' } });
  assert.equal((await call('POST', '/api/ingest', { headers: { 'x-api-key': key }, body: { events: evs } })).body.accepted, 15);
  const inc = await until(async () => (await call('GET', '/api/state', { s: admin })).body.incidents.find((i) => i.actions > 0 && i.pendingApprovals > 0));
  const full = (await call('GET', `/api/incidents/${inc.id}`, { s: admin })).body;
  assert.ok(full.containment.length > 0); assert.ok(full.containment.every((a) => a.tier !== 'automatic'), 'no automatic tier in production'); assert.ok(full.containment.every((a) => !['executed'].includes(a.status)), 'nothing executed without approval');
  assert.equal(full.alerts[0].origin ?? 'ingested', 'ingested');
  // approve one: no connector configured => manual_required, never "executed"
  const first = full.containment.find((a) => a.status === 'pending_approval');
  const ap = await call('POST', `/api/actions/${first.id}/approve`, { s: admin, body: { comment: 'ok' } }); assert.equal(ap.status, 200);
  const after = await until(async () => { const i = (await call('GET', `/api/incidents/${inc.id}`, { s: admin })).body; const a = i.containment.find((x) => x.id === first.id); return ['manual_required', 'dry_run', 'executed', 'failed'].includes(a.status) && i; });
  assert.equal(after.containment.find((x) => x.id === first.id).status, 'manual_required', 'no connector => honest manual_required');
  assert.notEqual(after.state, 'RESOLVED', 'an incident with unapplied containment must not auto-resolve');
});
test('restart: incident survives, in-flight work is flagged for a human, audit chain intact', async () => {
  await stop(); await start();
  const s = await call('POST', '/api/auth/login', { body: { username: 'root', password: 'long-enough-pass-1' } }); assert.equal(s.status, 200);
  const sess = { cookie: s.headers.get('set-cookie').split(';')[0], csrf: s.body.csrf };
  const st = (await call('GET', '/api/state', { s: sess })).body; assert.ok(st.incidents.length >= 1); assert.ok(st.incidents.every((i) => ['RESOLVED', 'CLOSED'].includes(i.state) || i.status === 'Needs Attention'));
  assert.equal((await call('GET', '/api/audit/verify', { s: sess })).body.ok, true); assert.equal((await call('GET', '/readyz')).status, 200);
});
test('SIGTERM shuts down cleanly (exit code 0) after flushing', async () => { const code = await new Promise((r) => { child.on('exit', (c) => r(c)); child.kill('SIGTERM'); }); assert.equal(code, 0); });
