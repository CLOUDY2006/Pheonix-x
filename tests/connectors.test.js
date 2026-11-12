'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const crypto = require('crypto');
const cfg = require('../server/core/config');
const guardian = require('../server/agents/guardian');
const recovery = require('../server/agents/recovery');

// ---- mock providers ----
const seen = []; let oktaStatus = 'ACTIVE', oktaStick = false, entraEnabled = true, hookConfirm = true;
const mock = http.createServer((req, res) => {
  let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
    seen.push({ method: req.method, url: req.url, headers: req.headers, body: b });
    const send = (c, o) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    let m;
    if (req.url.startsWith('/okta/')) {
      if (req.headers.authorization !== 'SSWS tok123') return send(401, {});
      if ((m = req.url.match(/users\/([^/]+)\/lifecycle\/suspend/))) { if (!oktaStick) oktaStatus = 'SUSPENDED'; return send(200, {}); }
      if (req.url.includes('/lifecycle/unsuspend')) { oktaStatus = 'ACTIVE'; return send(200, {}); }
      if (req.url.includes('/sessions')) return send(204, {});
      return send(200, { status: oktaStatus });
    }
    if (req.url.startsWith('/entra/') && req.url.includes('oauth2')) return send(200, { access_token: 'graph-token', expires_in: 3600 });
    if (req.url.startsWith('/graph/')) {
      if (req.headers.authorization !== 'Bearer graph-token') return send(401, {});
      if (req.method === 'PATCH') { entraEnabled = JSON.parse(b).accountEnabled; return send(204, {}); }
      if (req.url.includes('revokeSignInSessions')) return send(200, { value: true });
      return send(200, { accountEnabled: entraEnabled });
    }
    if (req.url.startsWith('/hook')) return send(200, { confirmed: hookConfirm, detail: 'hook ok' });
    send(404, {});
  });
});
let url;
test.before(async () => { await new Promise((r) => mock.listen(0, '127.0.0.1', r)); url = 'http://127.0.0.1:' + mock.address().port; Object.assign(process.env, { OKTA_URL: url + '/okta', OKTA_API_TOKEN: 'tok123', ENTRA_TENANT_ID: 't', ENTRA_CLIENT_ID: 'c', ENTRA_CLIENT_SECRET: 's', ENTRA_AUTHORITY: url + '/entra', ENTRA_GRAPH: url + '/graph', PHOENIX_WEBHOOK_URL: url + '/hook', PHOENIX_WEBHOOK_SECRET: 'shh' }); });
test.after(() => mock.close());
const act = (type, target) => ({ id: 'act-' + Math.random().toString(36).slice(2), type, target, tier: guardian.classify(type, target).tier, status: 'planned', description: type + ' ' + JSON.stringify(target) });
const reset = () => { seen.length = 0; oktaStatus = 'ACTIVE'; oktaStick = false; entraEnabled = true; hookConfirm = true; };

test('live connector default is DRY-RUN: nothing leaves the box', async () => {
  reset(); cfg.connectors.identity = 'okta'; cfg.connectorDryRun = true;
  const a = act('disable_account', { user: 'alice@corp.example' }); const r = await guardian.execute(a, { approvedBy: 'admin' });
  assert.equal(a.status, 'dry_run'); assert.equal(r.ok, false); assert.equal(seen.length, 0); assert.match(a.result.detail, /DRY-RUN/);
});
test('Okta: suspends, reads back SUSPENDED, rolls back with confirmation', async () => {
  reset(); cfg.connectors.identity = 'okta'; cfg.connectorDryRun = false;
  const a = act('disable_account', { user: 'alice@corp.example' }); const r = await guardian.execute(a, { incidentId: 'INC-1', approvedBy: 'admin' });
  assert.equal(r.ok, true); assert.equal(a.status, 'executed'); assert.equal(a.result.providerConfirmed, true); assert.equal(a.result.provider, 'okta'); assert.equal(oktaStatus, 'SUSPENDED');
  assert.ok(seen.some((s) => s.url.includes('/lifecycle/suspend')) && seen.some((s) => s.method === 'GET'));
  const rb = await guardian.rollback(a, 'INC-1', 'admin'); assert.equal(rb.ok, true); assert.equal(oktaStatus, 'ACTIVE'); assert.equal(a.status, 'rolled_back');
});
test('Okta: if the read-back does not show SUSPENDED the action is FAILED, never reported as done', async () => {
  reset(); oktaStick = true; cfg.connectors.identity = 'okta'; cfg.connectorDryRun = false;
  const a = act('disable_account', { user: 'bob@corp.example' }); const r = await guardian.execute(a, { approvedBy: 'admin' });
  assert.equal(r.ok, false); assert.equal(a.status, 'failed'); assert.match(a.error, /did not confirm/);
});
test('Entra: client-credentials token, disable, revoke sessions, read-back', async () => {
  reset(); cfg.connectors.identity = 'entra'; cfg.connectorDryRun = false;
  const a = act('disable_account', { user: 'carol@corp.example' }); const r = await guardian.execute(a, { approvedBy: 'admin' });
  assert.equal(r.ok, true); assert.equal(entraEnabled, false); assert.ok(seen.some((s) => s.url.includes('revokeSignInSessions')));
  const rb = await guardian.rollback(a, null, 'admin'); assert.equal(rb.ok, true); assert.equal(entraEnabled, true);
});
test('Webhook: HMAC-signed, idempotency key, provider can refuse confirmation', async () => {
  reset(); cfg.connectors.network = 'webhook'; cfg.connectorDryRun = false;
  const a = act('block_ip', { ip: '198.51.100.7' }); a.tier = 'automatic'; const r = await guardian.execute(a, { approvedBy: 'policy:automatic' });
  assert.equal(r.ok, true); const req = seen.find((s) => s.url.startsWith('/hook'));
  assert.equal(req.headers['x-phoenix-signature'], 'sha256=' + crypto.createHmac('sha256', 'shh').update(req.body).digest('hex')); assert.equal(req.headers['idempotency-key'], a.id + ':execute');
  reset(); hookConfirm = false; const b = act('block_ip', { ip: '198.51.100.8' }); const r2 = await guardian.execute(b, { approvedBy: 'policy:automatic' }); assert.equal(r2.ok, false); assert.equal(b.status, 'failed');
});
test('no connector => manual_required, and RECOVERY turns it into a human task that confirms it', async () => {
  reset(); cfg.connectors.endpoint = 'none';
  const a = act('isolate_host', { host: 'srv-9' }); const r = await guardian.execute(a, { approvedBy: 'admin' });
  assert.equal(a.status, 'manual_required'); assert.equal(r.pending, true);
  const inc = { id: 'INC-9', alerts: [], containment: [a], recovery: { tasks: [] } }; const inv = { affectedAssets: [], timeline: [] };
  const plan = recovery.plan(inc, inv, [a]); const t = plan.tasks.find((x) => x.kind === 'manual_action'); assert.ok(t); assert.equal(t.owner, 'human');
  inc.recovery = plan; await recovery.runTask(t, inc, 'analyst1'); assert.equal(a.status, 'executed'); assert.equal(a.result.manual, true); assert.equal(a.result.confirmedBy, 'analyst1');
  const v = recovery.verify(inc, 0); assert.ok(v.checks.find((c) => c.pass && /applied manually/.test(c.detail)));
});
test('restricted actions are refused even with live connectors', async () => {
  reset(); cfg.connectors.endpoint = 'webhook'; cfg.connectorDryRun = false;
  for (const type of ['wipe_host', 'shutdown_host', 'delete_data', 'modify_security_control', 'format_c_drive']) { const a = act(type, { host: 'srv-1' }); const r = await guardian.execute(a, { approvedBy: 'admin' }); assert.equal(r.ok, false); assert.equal(a.status, 'blocked'); }
  assert.equal(seen.length, 0, 'no network call was made for restricted actions');
});
test('approval-tier action without approval is refused', async () => {
  reset(); require('../server/core/autonomy').setMode('watch', 'test'); cfg.connectors.identity = 'okta'; cfg.connectorDryRun = false; const a = act('disable_account', { user: 'x@y.z' }); const r = await guardian.execute(a, {}); assert.equal(r.ok, false); assert.equal(seen.length, 0);
});
