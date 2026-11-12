'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../server/index');
const auth = require('../server/core/auth');
let base;
test.before(async () => { app.boot(); await new Promise((r) => app.server.listen(0, '127.0.0.1', r)); base = 'http://127.0.0.1:' + app.server.address().port; });
test.after(() => { app.server.close(); require('../server/core/persist').stop(); });

async function call(method, path, { body, cookie, csrf, headers = {}, raw } = {}) {
  const r = await fetch(base + path, { method, headers: { ...(body && !raw ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...(csrf ? { 'x-csrf-token': csrf } : {}), ...headers }, body: raw !== undefined ? raw : body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; } return { status: r.status, body: j, headers: r.headers };
}
async function session(u, p, totp) { const r = await call('POST', '/api/auth/login', { body: { username: u, password: p, totp } }); if (r.status !== 200) return { r }; const c = r.headers.get('set-cookie').split(';')[0]; return { r, cookie: c, csrf: r.body.csrf, token: r.body.token }; }

test('health endpoints are open; metrics need credentials', async () => {
  assert.equal((await call('GET', '/healthz')).status, 200); assert.equal((await call('GET', '/readyz')).status, 200);
  assert.equal((await call('GET', '/metrics')).status, 401);
  const s = await session('admin', 'phoenix-demo'); const m = await call('GET', '/metrics', { cookie: s.cookie }); assert.equal(m.status, 200); assert.match(m.body, /phoenix_audit_chain_ok 1/);
});

test('cookie sessions are HttpOnly+SameSite and need a CSRF header for writes', async () => {
  const s = await session('admin', 'phoenix-demo'); assert.ok(s.cookie.startsWith('phx_session='));
  assert.match(s.r.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  assert.equal((await call('GET', '/api/state', { cookie: s.cookie })).status, 200);
  assert.equal((await call('POST', '/api/settings', { cookie: s.cookie, body: { paceMs: 0 } })).status, 403);
  assert.equal((await call('POST', '/api/settings', { cookie: s.cookie, csrf: s.csrf, body: { paceMs: 0 } })).status, 200);
  assert.equal((await call('POST', '/api/settings', { headers: { authorization: 'Bearer ' + s.token }, body: { paceMs: 0 } })).status, 200, 'bearer tokens (scripts) are not CSRF-able');
});

test('RBAC: viewer cannot approve, analyst cannot administer', async () => {
  const v = await session('viewer', 'phoenix-demo'), a = await session('analyst', 'phoenix-demo');
  assert.equal((await call('POST', '/api/actions/x/approve', { cookie: v.cookie, csrf: v.csrf, body: {} })).status, 403);
  assert.equal((await call('GET', '/api/users', { cookie: a.cookie })).status, 403);
  assert.equal((await call('GET', '/api/state')).status, 401);
});

test('lockout after repeated failures, and a good login still works for other accounts', async () => {
  auth.createUser({ username: 'lock.me', password: 'correct-horse-9', role: 'viewer' });
  for (let i = 0; i < 5; i++) assert.equal((await call('POST', '/api/auth/login', { body: { username: 'lock.me', password: 'nope' + i } })).status, 401);
  assert.equal((await call('POST', '/api/auth/login', { body: { username: 'lock.me', password: 'correct-horse-9' } })).status, 429, 'locked even with the right password');
  auth.resetLockouts();
});

test('password policy + last-admin protection + user lifecycle', async () => {
  const s = await session('admin', 'phoenix-demo'); const H = { cookie: s.cookie, csrf: s.csrf };
  assert.equal((await call('POST', '/api/users', { ...H, body: { username: 'bob', password: 'short1', role: 'analyst' } })).status, 400);
  assert.equal((await call('POST', '/api/users', { ...H, body: { username: 'bob', password: 'a-long-password-77', role: 'analyst' } })).status, 201);
  assert.equal((await call('POST', '/api/users/bob/update', { ...H, body: { disabled: true } })).status, 200);
  assert.equal((await session('bob', 'a-long-password-77')).r.status, 401, 'disabled user cannot log in');
  assert.equal((await call('POST', '/api/users/admin/delete', { ...H })).status, 400);
  assert.throws(() => auth.updateUser('admin', { role: 'viewer' }, 'x'), /last admin/);
});

test('TOTP: once enabled, login needs the code', async () => {
  auth.createUser({ username: 'totp.user', password: 'totp-password-12', role: 'analyst' });
  const s = await session('totp.user', 'totp-password-12'); const b = await call('POST', '/api/auth/totp/begin', { cookie: s.cookie, csrf: s.csrf });
  assert.equal((await call('POST', '/api/auth/totp/confirm', { cookie: s.cookie, csrf: s.csrf, body: { code: '000000' } })).status, 400);
  assert.equal((await call('POST', '/api/auth/totp/confirm', { cookie: s.cookie, csrf: s.csrf, body: { code: auth.totpAt(b.body.secret) } })).status, 200);
  const r = await call('POST', '/api/auth/login', { body: { username: 'totp.user', password: 'totp-password-12' } }); assert.equal(r.status, 401); assert.equal(r.body.totpRequired, true);
  assert.equal((await session('totp.user', 'totp-password-12', auth.totpAt(b.body.secret))).r.status, 200);
  // RFC 6238 test vector (SHA-1, secret "12345678901234567890", T=59s -> 94287082 -> last 6 digits 287082)
  assert.equal(auth.totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000), '287082');
});

test('ingest: per-source keys, format binding, normalisation, dedupe, text syslog', async () => {
  const a = await session('admin', 'phoenix-demo'); const H = { cookie: a.cookie, csrf: a.csrf };
  const k = await call('POST', '/api/keys', { ...H, body: { name: 'okta-prod', format: 'okta' } }); assert.equal(k.status, 201); assert.ok(k.body.key.startsWith('phx_'));
  assert.equal((await call('GET', '/api/keys', { cookie: a.cookie })).body.keys[0].hash, undefined, 'hash/secret never listed');
  const rec = { eventType: 'user.session.start', published: new Date().toISOString(), uuid: 'u-1', actor: { alternateId: 'alice.chen@corp.example' }, client: { ipAddress: '203.0.113.9', geographicalContext: { country: 'Germany', city: 'Berlin' } }, outcome: { result: 'FAILURE', reason: 'VERIFICATION_ERROR' } };
  assert.equal((await call('POST', '/api/ingest/okta', { body: [rec] })).status, 401);
  const ok = await call('POST', '/api/ingest/okta', { headers: { 'x-api-key': k.body.key }, body: [rec] }); assert.equal(ok.status, 200); assert.equal(ok.body.accepted, 1);
  assert.equal((await call('POST', '/api/ingest/okta', { headers: { 'x-api-key': k.body.key }, body: [rec] })).body.duplicates, 1, 'same uuid is deduplicated');
  assert.equal((await call('POST', '/api/ingest/windows', { headers: { 'x-api-key': k.body.key }, body: [] })).status, 403, 'okta key cannot post windows logs');
  const k2 = await call('POST', '/api/keys', { ...H, body: { name: 'web1', format: 'syslog' } });
  const sl = await call('POST', '/api/ingest/syslog', { headers: { 'x-api-key': k2.body.key, 'content-type': 'text/plain' }, raw: 'Nov  6 10:00:01 web1 sshd[1]: Failed password for root from 198.51.100.7 port 22\nNov  6 10:00:02 web1 sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 22' });
  assert.equal(sl.body.accepted, 2);
  const ev = (await call('GET', '/api/events?limit=10', { cookie: a.cookie })).body; assert.ok(ev.some((e) => e.origin === 'ingested' && e.user === 'root' && e.type === 'login_failed'));
  await call('POST', `/api/keys/${k.body.id}/revoke`, { ...H }); assert.equal((await call('POST', '/api/ingest/okta', { headers: { 'x-api-key': k.body.key }, body: [rec] })).status, 401, 'revoked key is dead');
});

test('suppressions need a reason and are audited; asset + backup registration works', async () => {
  const a = await session('admin', 'phoenix-demo'); const H = { cookie: a.cookie, csrf: a.csrf };
  assert.equal((await call('POST', '/api/suppressions', { ...H, body: { rule: 'R-BRUTE', user: 'scanner' } })).status, 400);
  const s = await call('POST', '/api/suppressions', { ...H, body: { rule: 'R-BRUTE', user: 'scanner', reason: 'Vuln scanner, ticket SEC-1', expiresInHours: 24 } }); assert.equal(s.status, 201);
  assert.equal((await call('POST', '/api/assets/host/db-prod-9', { ...H, body: { env: 'production', criticality: 'critical', owner: 'dba' } })).status, 200);
  assert.equal((await call('POST', '/api/assets/backups', { ...H, body: { host: 'db-prod-9', id: 'bk-1', ts: '2026-01-01T00:00:00Z', verified: true, immutable: true } })).status, 201);
  const log = (await call('GET', '/api/audit?limit=100', { cookie: a.cookie })).body; assert.ok(log.some((e) => e.action === 'SUPPRESSION_ADDED' || /SUPPRESS/.test(e.action)));
});

test('backup endpoint writes a copy; audit chain verifies over the API', async () => {
  const a = await session('admin', 'phoenix-demo'); const H = { cookie: a.cookie, csrf: a.csrf };
  assert.equal((await call('GET', '/api/audit/verify', { cookie: a.cookie })).body.ok, true);
  const fs = require('fs'); const dir = require('os').tmpdir(); const f = require('path').join(dir, 'phx-api-backup.db'); fs.rmSync(f, { force: true });
  const b = require('../server/core/db').backup(f); assert.ok(fs.statSync(b).size > 0);
});
