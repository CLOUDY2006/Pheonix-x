'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const h = require('./helpers');
const cfg = require('../server/core/config');
const cmd = require('../server/agents/commander');
const assistant = require('../server/agents/assistant');
const auth = require('../server/core/auth');
const connectors = require('../server/connectors');
const recovery = require('../server/agents/recovery');
const admin = { sub: 'admin', role: 'admin' }, analyst = { sub: 'analyst', role: 'analyst' }, viewer = { sub: 'viewer', role: 'viewer' };
const say = (u, t) => assistant.handle(u, t);

test('chat: "block <ip>" is done by the AI, "block this ip" uses the IP from the conversation, undo works, roles enforced', async () => {
  h.fresh(); assistant.reset();
  assert.match((await say(viewer, 'block 198.51.100.23')).reply, /analyst/);
  let r = await say(analyst, 'block 198.51.100.23'); assert.match(r.reply, /Done/); assert.ok(h.sim.env.firewall.blockedIPs.has('198.51.100.23'));
  assert.ok(cmd.containments().some((c) => c.target.ip === '198.51.100.23' && c.incidentId === 'MANUAL'), 'listed under active blocks');
  await say(analyst, 'activity for 198.51.100.77'); r = await say(analyst, 'block this ip'); assert.match(r.reply, /198\.51\.100\.77/); assert.ok(h.sim.env.firewall.blockedIPs.has('198.51.100.77'));
  r = await say(analyst, 'block 10.1.2.3'); assert.match(r.reply, /internal address/); assert.equal(h.sim.env.firewall.blockedIPs.has('10.1.2.3'), false);
  r = await say(analyst, 'no'); assert.match(r.reply, /did not/); assert.match((await say(analyst, 'block 999.1.1.1')).reply, /not a valid/);
  r = await say(analyst, 'unblock 198.51.100.23'); assert.match(r.reply, /Unblocked/); assert.equal(h.sim.env.firewall.blockedIPs.has('198.51.100.23'), false);
  assert.ok(h.audit.recent(500).some((e) => e.action === 'MANUAL_ACTION'));
});

test('chat: disable / reset password / isolate need an admin and a confirmation; ambiguous names ask which', async () => {
  h.fresh(); assistant.reset(); const users = Object.keys(h.sim.env.users);
  assert.match((await say(analyst, 'disable alice.chen')).reply, /admin/);
  let r = await say(admin, 'suspend alice.chen'); assert.match(r.reply, /Say \*\*yes\*\*/); assert.equal(h.sim.env.users['alice.chen'].status, 'active', 'not before confirmation');
  r = await say(admin, 'yes'); assert.match(r.reply, /Done/); assert.equal(h.sim.env.users['alice.chen'].status, 'suspended');
  r = await say(admin, 'unblock alice.chen'); assert.match(r.reply, /Unblocked/); assert.equal(h.sim.env.users['alice.chen'].status, 'active');
  r = await say(admin, 'reset password for bob.martin'); assert.match(r.reply, /Done/); assert.equal(h.sim.env.users['bob.martin'].passwordResetRequired, true);
  const dup = users.filter((x) => x.includes('.')).map((x) => x.split('.')[0]).find((f, i, a) => a.indexOf(f) !== i);
  if (dup) { r = await say(admin, 'revoke sessions for ' + dup); assert.match(r.reply, /Which one/); }
  r = await say(admin, 'isolate ws-carol-01'); assert.match(r.reply, /yes/); r = await say(admin, 'yes'); assert.match(r.reply, /Done/); assert.equal(h.sim.env.hosts['ws-carol-01'].isolated, true);
  r = await say(admin, 'unblock ws-carol-01'); assert.match(r.reply, /Unblocked/); assert.equal(h.sim.env.hosts['ws-carol-01'].isolated, false);
});

test('chat answers questions: why, activity, who is, glossary, risk, rotate all keys', async () => {
  const inc = await h.run('credential-compromise', { mode: 'balanced' }); await h.settled(inc); assistant.reset();
  const ip = inc.containment.find((a) => a.type === 'block_ip').target.ip;
  let r = await say(viewer, 'why was ' + ip + ' blocked?'); assert.match(r.reply, /Because of INC-/); assert.match(r.reply, /R-/);
  r = await say(viewer, 'activity for alice.chen'); assert.match(r.reply, /event/); r = await say(viewer, 'who is alice.chen'); assert.match(r.reply, /Incidents: INC-/);
  assert.match((await say(viewer, 'what is ransomware?')).reply, /encrypts files/); assert.match((await say(viewer, 'explain mfa')).reply, /second proof/);
  assert.match((await say(viewer, 'how safe are we')).reply, /incident|threat/); assert.match((await say(viewer, 'list incidents')).reply, /INC-/);
  auth.createKey({ name: 'k1', format: 'generic' }, 'admin'); auth.createKey({ name: 'k2', format: 'nginx' }, 'admin');
  assert.match((await say(admin, 'rotate all keys')).reply, /Say \*\*yes\*\*/); r = await say(admin, 'yes'); assert.match(r.reply, /Rotated \*\*\d+\*\*/); assert.equal(auth.listKeys().filter((k) => !k.disabled).length >= 2, true);
});

test('chat falls back to the language model only when enabled, and the model cannot act', async () => {
  let seen; const srv = http.createServer((q, s) => { let b = ''; q.on('data', (d) => (b += d)); q.on('end', () => { seen = JSON.parse(b); s.writeHead(200, { 'content-type': 'application/json' }); s.end(JSON.stringify({ content: [{ text: 'Use a firewall rule.' }] })); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); Object.assign(process.env, { PHOENIX_API_ANTHROPIC: 'http://127.0.0.1:' + srv.address().port, ANTHROPIC_API_KEY: 'k' });
  try {
    delete process.env.PHOENIX_CHAT_LLM; assert.match((await say(viewer, 'tell me a joke about firewalls')).reply, /didn't understand/); assert.equal(seen, undefined, 'nothing sent unless enabled');
    process.env.PHOENIX_CHAT_LLM = 'on'; const r = await say(viewer, 'how do i harden my router?'); assert.match(r.reply, /Use a firewall rule/); assert.match(seen.system, /cannot execute actions/);
  } finally { srv.close(); delete process.env.PHOENIX_CHAT_LLM; delete process.env.ANTHROPIC_API_KEY; delete process.env.PHOENIX_API_ANTHROPIC; }
});

test('Okta: AI forces the password reset (provider-confirmed), and "check" detects the user finished the reset', async () => {
  let changed = null; const calls = [];
  const srv = http.createServer((q, s) => { calls.push(q.method + ' ' + q.url); const j = (o, c = 200) => { s.writeHead(c, { 'content-type': 'application/json' }); s.end(JSON.stringify(o)); };
    if (q.url.endsWith('/lifecycle/expire_password')) return j({ status: 'PASSWORD_EXPIRED' }); if (q.method === 'DELETE') return j({}, 204); if (q.method === 'GET') return j({ status: changed ? 'ACTIVE' : 'PASSWORD_EXPIRED', passwordChanged: changed }); j({}); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); const old = { ...cfg.connectors }; const dry = cfg.connectorDryRun;
  Object.assign(process.env, { OKTA_URL: 'http://127.0.0.1:' + srv.address().port, OKTA_API_TOKEN: 't' }); cfg.connectors.identity = 'okta'; cfg.connectorDryRun = false;
  try {
    h.fresh('watch'); const g = require('../server/agents/guardian'); const a = g.mk('force_password_reset', { user: 'alice@acme.com' }, 'test');
    const r = await g.execute(a, { approvedBy: 'admin' }); assert.equal(r.ok, true); assert.equal(a.status, 'executed'); assert.equal(a.result.providerConfirmed, true); assert.ok(calls.some((c) => c.includes('expire_password')));
    const since = new Date(Date.now() - 1000).toISOString(); assert.deepEqual((({ known, done }) => ({ known, done }))(await connectors.checkPasswordChanged('alice@acme.com', since)), { known: true, done: false });
    changed = new Date().toISOString(); assert.equal((await connectors.checkPasswordChanged('alice@acme.com', since)).done, true);
    // a pending human step is auto-completed once the provider shows the change
    const inc = { id: 'INC-C1', createdAt: since, state: 'RECOVERING', alerts: [], containment: [], messages: [], workflow: {}, recovery: { tasks: [{ id: 'tk1', kind: 'reset_credentials', owner: 'human', user: 'alice@acme.com', status: 'pending', checkable: true, title: 'Reset', createdAt: since }] } };
    cmd.incidents.set(inc.id, inc); try { changed = null; assert.equal((await cmd.checkTask(inc.id, 'tk1')).done, false); assert.equal(inc.recovery.tasks[0].status, 'pending'); changed = new Date().toISOString(); assert.equal((await cmd.checkTask(inc.id, 'tk1')).done, true); assert.equal(inc.recovery.tasks[0].status, 'done'); } finally { cmd.incidents.delete(inc.id); }
  } finally { srv.close(); Object.assign(cfg.connectors, old); cfg.connectorDryRun = dry; delete process.env.OKTA_URL; delete process.env.OKTA_API_TOKEN; }
});

test('production recovery is minimal: no human step when the AI already reset the password; links + check shown when it could not', async () => {
  const inc = await h.run('credential-compromise', { mode: 'balanced' }); await h.settled(inc);
  const wasProd = cfg.isProd; cfg.isProd = true;
  try {
    const act = (t) => inc.containment.find((a) => a.type === t);
    const rst = act('force_password_reset'); assert.ok(rst && act('disable_account'), 'the AI plans a reset and a suspension');
    const mkTasks = () => recovery.plan(inc, inc.investigation, inc.containment).tasks.filter((t) => t.user === 'alice.chen');
    rst.status = 'executed'; rst.result = { provider: 'okta', providerConfirmed: true }; act('disable_account').status = 'executed';
    let T = mkTasks(); assert.deepEqual(T.map((t) => t.kind), ['reenable_account'], 'AI did the reset: only the AI re-enable remains'); assert.equal(T[0].owner, 'RECOVERY'); assert.ok(!T[0].dependsOn);
    rst.status = 'dry_run'; rst.result = { provider: 'okta', providerConfirmed: false };
    T = mkTasks(); const human = T.find((t) => t.owner === 'human'); assert.ok(human, 'a human step appears'); assert.ok(human.links.length && human.links[0].url.startsWith('https://')); assert.equal(human.checkable, true); assert.equal(T.filter((t) => t.owner === 'human').length, 1, 'a single step');
  } finally { cfg.isProd = wasProd; }
});
