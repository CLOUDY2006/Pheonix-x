'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers');
const oracle = require('../server/agents/oracle');
const guardian = require('../server/agents/guardian');
const { validate, SPECS } = require('../server/core/schema');

const types = (inc) => inc.containment.map((a) => a.type);
const finish = async (id, mode) => { const inc = await h.run(id, { mode }); await h.settled(inc); return inc; };

test('1 credential compromise: detected, contained, session revoked, resolved, verified', async () => {
  const inc = await finish('credential-compromise');
  assert.equal(inc.state, 'RESOLVED'); assert.ok(inc.verification.passed);
  assert.ok(inc.alerts.some((a) => a.rule === 'R-CRED-COMPROMISE'));
  assert.ok(types(inc).includes('revoke_sessions') && types(inc).includes('block_ip'));
  assert.equal(h.sim.env.users['alice.chen'].sessions.length, 0);
  assert.ok(inc.investigation.techniques.some((t) => t.id === 'T1078' && t.status === 'evidence-supported'));
  assert.ok(inc.investigation.hypotheses.length > 0, 'hypotheses kept separate from confirmed findings');
  assert.ok(inc.report.includes('Executive summary'));
});

test('2 ransomware: hosts isolated with approval, backup-gap detected, restricted actions never executed', async () => {
  const inc = await finish('ransomware');
  assert.ok(inc.alerts.some((a) => a.rule === 'R-RANSOMWARE'));
  const iso = inc.containment.filter((a) => a.type === 'isolate_host'); assert.equal(iso.length, 2);
  assert.ok(iso.every((a) => a.tier === 'approval' && a.approvedBy));
  const ready = Object.fromEntries(inc.recovery.readiness.map((r) => [r.host, r.status]));
  assert.equal(ready['srv-files-01'], 'ready'); assert.equal(ready['ws-carol-01'], 'no-backup');
  assert.ok(inc.recovery.tasks.some((t) => t.kind === 'restore_backup' && t.status === 'done'));
  assert.ok(inc.recovery.tasks.some((t) => t.kind === 'manual_rebuild'));
  assert.ok(inc.plan.manualOnly.some((m) => m.type === 'wipe_host') && inc.plan.manualOnly.some((m) => m.type === 'shutdown_host'));
  assert.ok(h.audit._chain.some((e) => e.action === 'POLICY_RESTRICTED'));
  assert.ok(!inc.containment.some((a) => ['wipe_host', 'shutdown_host', 'delete_data'].includes(a.type)));
});

test('3 insider threat (Watch mode): account suspension needs approval; unknown IP is not called malicious', async () => {
  const inc = await finish('insider-threat', 'watch');
  const dis = inc.containment.find((a) => a.type === 'disable_account'); assert.equal(dis.tier, 'approval'); assert.ok(dis.approvedBy);
  const ind = inc.intel.indicators.find((i) => i.indicator === '198.19.120.40'); assert.equal(ind.verdict, 'unknown');
  assert.ok(inc.alerts.some((a) => a.rule === 'R-MASS-DOWNLOAD') && inc.alerts.some((a) => a.rule === 'R-PRIV'));
});

test('4 phishing: static email analysis, no URL fetched, clickers found, ticket created', async () => {
  const inc = await finish('phishing');
  assert.equal(inc.emailAnalysis.urlsFetched, false);
  assert.deepEqual(inc.emailAnalysis.clickers.sort(), ['alice.chen', 'erin.novak']);
  assert.ok(inc.emailAnalysis.domains.includes('secure-payroll-login.example'));
  assert.ok(inc.intel.indicators.find((i) => i.indicator === 'secure-payroll-login.example').verdict === 'malicious');
  assert.ok(inc.ticket && /^PHX-/.test(inc.ticket.id) && inc.ticket.confirmed === false, 'simulated ticket must not claim to be confirmed');
});

test('5 cloud compromise: admin policy detached, bucket private, logging control left to humans', async () => {
  const inc = await finish('cloud-compromise');
  assert.ok(!h.sim.env.cloud.roles['dev-sandbox-role'].policies.includes('AdministratorAccess'));
  assert.equal(h.sim.env.cloud.buckets['phx-demo-finance-exports'].public, false);
  assert.ok(inc.plan.manualOnly.some((m) => m.type === 'modify_security_control'));
  assert.ok(h.sim.env.firewall.blockedIPs.has('198.19.88.23'));
});

test('6 benign travel: triaged to monitor, no containment (no over-reaction)', async () => {
  const inc = await finish('benign-travel');
  assert.equal(inc.disposition, 'monitor'); assert.equal(inc.containment.length, 0); assert.equal(inc.priority, 'P4');
  assert.equal(h.sim.env.users['bob.martin'].status, 'active');
});

test('approval gate: nothing high-impact runs until a human approves; rejection is respected', async () => {
  h.fresh(); h.autonomy.setMode('watch', 'test', { silent: true }); h.cmd.settings.autopilot = false;
  await require('../server/scenarios').launch('credential-compromise', { speed: 0 });
  const inc = await h.until(() => [...h.cmd.incidents.values()][0]);
  await h.until(() => h.cmd.pendingFor().length > 0);
  assert.equal(h.sim.env.users['alice.chen'].status, 'active', 'account must NOT be suspended before approval');
  assert.equal(inc.state, 'AWAITING_APPROVAL');
  assert.ok(inc.containment.filter((a) => a.tier === 'automatic').every((a) => ['executed', 'planned'].includes(a.status)));
  const p = h.cmd.pendingFor().find((x) => x.action.type === 'disable_account').action; for (const x of h.cmd.pendingFor()) await h.cmd.decide(x.action.id, false, 'admin', 'not now');
  await h.until(() => inc.state === 'RECOVERING' || inc.state === 'VERIFYING');
  assert.equal(h.sim.env.users['alice.chen'].status, 'active'); assert.equal(p.status, 'denied');
  h.cmd.setAutopilot(true); // let tasks finish
  await h.until(() => inc.verification, 8000);
  assert.equal(inc.verification.passed, false, 'a rejected containment is reported as residual risk, not hidden');
});

test('policy engine: restricted & unknown actions are refused even when "approved"', async () => {
  h.fresh(); h.autonomy.setMode('watch', 'test', { silent: true });
  for (const type of ['delete_data', 'shutdown_host', 'wipe_host', 'modify_security_control', 'rm_rf', 'eval']) {
    const r = await guardian.execute({ id: 'x', type, target: { host: 'srv-files-01' } }, { approvedBy: 'admin' }); assert.equal(r.ok, false, type); assert.equal(r.blocked, true);
  }
  assert.equal(h.sim.env.hosts['srv-files-01'].status, 'online');
  h.autonomy.setMode('balanced', 'test', { silent: true }); assert.equal(guardian.classify('block_ip', { ip: '198.19.66.14' }).tier, 'automatic'); assert.equal(guardian.classify('block_ip', { host: 'prod-db-01' }).tier, 'approval');
  assert.equal(guardian.classify('restrict_resource', { resource: '/prod/customers.db' }).tier, 'approval', 'production assets are never automatic');
  h.autonomy.setMode('watch', 'test', { silent: true }); const r = await guardian.execute({ id: 'y', type: 'disable_account', target: { user: 'alice.chen' } }, {}); assert.equal(r.ok, false, 'approval-tier needs an approver');
});

test('threat intel: unknown indicators are never malicious', async () => {
  const r = await oracle.lookup('ip', '203.0.113.200'); assert.equal(r.verdict, 'unknown');
  assert.equal((await oracle.lookup('ip', '198.19.66.77')).verdict, 'malicious');
});

test('audit trail is hash-chained and tamper-evident; evidence is hash-preserved', async () => {
  const inc = await finish('credential-compromise');
  assert.ok(h.audit.verify().ok); assert.ok(inc.evidence.sha256.length === 64);
  h.audit._chain[3].detail = { forged: true }; assert.equal(h.audit.verify().ok, false); assert.equal(h.audit.verify().brokenAt, 4);
});

test('agent failure never crashes the pipeline (degraded mode)', async () => {
  h.fresh(); const inv = require('../server/agents/investigator'); const orig = inv.investigate; inv.investigate = () => { throw new Error('boom'); };
  try { await require('../server/scenarios').launch('credential-compromise', { speed: 0 }); const inc = await h.until(() => [...h.cmd.incidents.values()][0]); await h.settled(inc); assert.equal(inc.degraded, true); assert.ok(inc.investigation.summary.startsWith('FALLBACK')); assert.ok(['RESOLVED'].includes(inc.state) || inc.status === 'Needs Attention'); }
  finally { inv.investigate = orig; }
});

test('schema validation rejects malformed agent output', () => {
  assert.equal(validate(SPECS.alert, { id: 'x' }).ok, false);
});
