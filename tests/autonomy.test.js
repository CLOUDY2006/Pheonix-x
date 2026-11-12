'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers');
const guardian = require('../server/agents/guardian');
const autonomy = require('../server/core/autonomy');
const S = { silent: true };

test('Balanced: the AI contains on its own (account suspended, IP blocked) and a human can unblock it', async () => {
  const inc = await h.run('credential-compromise', { mode: 'balanced' }); await h.settled(inc);
  const dis = inc.containment.find((a) => a.type === 'disable_account');
  assert.equal(dis.tier, 'automatic'); assert.equal(dis.aiAuto, true); assert.ok(['executed', 'rolled_back'].includes(dis.status), 'suspended by the AI (recovery may already have re-enabled it)'); assert.match(dis.rationale, /AI acted alone/);
  const blk = inc.containment.find((a) => a.type === 'block_ip');
  assert.equal(inc.approvals.length, 0, 'nothing waited for a human');
  assert.ok(h.audit.recent(2000).some((e) => e.action === 'AI_AUTO_ACTION'));
  const list = h.cmd.containments(); assert.ok(list.some((c) => c.id === blk.id && c.aiAuto));
  assert.ok(h.sim.env.firewall.blockedIPs.has(blk.target.ip));
  await h.cmd.undoAction(blk.id, 'analyst1', { reason: 'it was our contractor' });
  assert.equal(h.sim.env.firewall.blockedIPs.has(blk.target.ip), false); assert.equal(blk.status, 'rolled_back');
  assert.equal(guardian.classify('block_ip', { ip: blk.target.ip }).tier, 'approval', 'after an unblock the AI will not re-apply it alone');
  assert.ok(autonomy.isProtected({ ip: blk.target.ip }));
  await assert.rejects(() => h.cmd.undoAction(blk.id, 'analyst1'), /not active/);
});

test('Watch: the AI recommends only; every action waits for approval', async () => {
  h.fresh('watch'); h.cmd.settings.autopilot = false;
  await require('../server/scenarios').launch('credential-compromise', { speed: 0 });
  await h.until(() => h.cmd.pendingFor().length >= 2);
  assert.ok(h.cmd.pendingFor().every((p) => p.action.tier === 'approval'));
  assert.equal(h.sim.env.users['alice.chen'].status, 'active'); assert.equal(h.sim.env.firewall.blockedIPs.size, 0);
  h.cmd.setAutopilot(true); await h.until(() => [...h.cmd.incidents.values()][0].verification, 10000);
});

test('Full: cautious actions (isolate host) run alone; destructive ones never do, in any mode', async () => {
  autonomy.setMode('full', 't', S);
  assert.equal(guardian.classify('isolate_host', { host: 'ws-carol-01' }).tier, 'automatic');
  assert.equal(guardian.classify('detach_cloud_policy', { role: 'r', policy: 'p' }).tier, 'automatic');
  for (const m of ['watch', 'balanced', 'full']) { autonomy.setMode(m, 't', S); for (const t of ['wipe_host', 'shutdown_host', 'delete_data', 'modify_security_control', 'nonsense']) assert.equal(guardian.classify(t, { host: 'x' }).tier, 'restricted', m + ':' + t); }
  autonomy.setMode('balanced', 't', S); assert.equal(guardian.classify('isolate_host', { host: 'ws-carol-01' }).tier, 'approval');
});

test('protected entities and private IPs always need a human, even in Full', () => {
  autonomy.reset();
  autonomy.setMode('full', 't', S);
  assert.equal(guardian.classify('block_ip', { ip: '10.0.0.5' }).tier, 'approval'); assert.equal(guardian.classify('block_ip', { ip: '192.168.1.9' }).tier, 'approval');
  assert.equal(guardian.classify('block_ip', { ip: '198.19.66.14' }).tier, 'automatic');
  const e = autonomy.protect({ kind: 'ip', value: '198.19.66.14', reason: 'our office VPN' }, 'admin'); assert.equal(guardian.classify('block_ip', { ip: '198.19.66.14' }).tier, 'approval');
  autonomy.unprotect(e.id, 'admin'); assert.equal(guardian.classify('block_ip', { ip: '198.19.66.14' }).tier, 'automatic');
  assert.throws(() => autonomy.protect({ kind: 'ip', value: '1.2.3.4', reason: '' }, 'a'));
});

test('circuit breaker: after the hourly budget the AI falls back to asking a human', () => {
  autonomy.setMode('balanced', 't', S); const old = process.env.PHOENIX_AI_ACTION_BUDGET; process.env.PHOENIX_AI_ACTION_BUDGET = '2';
  const used = autonomy.status().budget.used; process.env.PHOENIX_AI_ACTION_BUDGET = String(used + 2);
  assert.equal(guardian.classify('block_ip', { ip: '198.19.1.1' }).tier, 'automatic'); autonomy.spend(); autonomy.spend();
  const c = guardian.classify('block_ip', { ip: '198.19.1.1' }); assert.equal(c.tier, 'approval'); assert.match(c.why, /Circuit breaker/);
  assert.equal(autonomy.status().budget.tripped, true);
  if (old === undefined) delete process.env.PHOENIX_AI_ACTION_BUDGET; else process.env.PHOENIX_AI_ACTION_BUDGET = old;
});

test('self-recovery: the AI lifts its own expired IP block; Watch mode never does', async () => {
  const inc = await h.run('credential-compromise', { mode: 'balanced' }); await h.settled(inc);
  const blk = inc.containment.find((a) => a.type === 'block_ip' && a.status === 'executed'); assert.ok(blk && blk.expiresAt, 'AI blocks carry a lifetime');
  blk.expiresAt = new Date(Date.now() - 1000).toISOString();
  autonomy.setMode('watch', 't', S); assert.equal(await h.cmd.sweepExpired(), 0); assert.equal(blk.status, 'executed');
  autonomy.setMode('balanced', 't', S); assert.ok((await h.cmd.sweepExpired()) >= 1);
  assert.equal(blk.status, 'rolled_back'); assert.equal(h.sim.env.firewall.blockedIPs.has(blk.target.ip), false);
  assert.ok(h.audit.recent(2000).some((e) => e.action === 'AI_SELF_RECOVERY'));
});

test('API: mode change is admin-only and audited; unblock is analyst, "trust" is admin', async () => {
  const app = require('../server/index'); app.boot(); await new Promise((r) => app.server.listen(0, '127.0.0.1', r)); const base = 'http://127.0.0.1:' + app.server.address().port;
  const call = async (m, p, s, body) => { const r = await fetch(base + p, { method: m, headers: { 'content-type': 'application/json', ...(s ? { cookie: s.cookie, 'x-csrf-token': s.csrf } : {}) }, body: body ? JSON.stringify(body) : undefined }); let j; try { j = await r.json(); } catch { j = null; } return { status: r.status, body: j }; };
  const login = async (u) => { const r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: u, password: 'phoenix-demo' }) }); const j = await r.json(); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: j.csrf }; };
  const admin = await login('admin'), analyst = await login('analyst'), viewer = await login('viewer');
  try {
    assert.equal((await call('POST', '/api/autonomy', analyst, { mode: 'full' })).status, 403);
    assert.equal((await call('POST', '/api/autonomy', admin, { mode: 'bogus' })).status, 400);
    const r = await call('POST', '/api/autonomy', admin, { mode: 'full' }); assert.equal(r.status, 200); assert.equal(r.body.mode, 'full');
    assert.ok(h.audit.recent(2000).some((e) => e.action === 'AUTONOMY_CHANGED' && e.detail?.to === 'full'));
    assert.equal((await call('GET', '/api/autonomy', viewer)).body.mode, 'full');
    h.fresh('balanced'); const inc = await h.run('credential-compromise', { mode: 'balanced' }); await h.settled(inc);
    const act = inc.containment.find((a) => a.type === 'block_ip' && a.status === 'executed');
    assert.equal((await call('POST', `/api/actions/${act.id}/undo`, viewer, {})).status, 403);
    assert.equal((await call('POST', `/api/actions/${act.id}/undo`, analyst, { trust: true })).status, 403);
    assert.equal((await call('GET', '/api/containments', viewer)).body.containments.some((c) => c.id === act.id), true);
    assert.equal((await call('POST', `/api/actions/${act.id}/undo`, admin, { trust: true, reason: 'known partner' })).status, 200);
    assert.equal(act.status, 'rolled_back'); assert.equal(autonomy.listProtected().find((p) => p.value === act.target.ip).expiresAt, null);
  } finally { app.server.close(); }
});
