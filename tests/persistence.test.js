'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'); const os = require('os'); const path = require('path');
const h = require('./helpers');
const persist = require('../server/core/persist');
const scen = require('../server/scenarios');
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'phx-')), 'p.db');

test('incidents, events and the audit chain survive a restart', async () => {
  const file = tmp(); h.fresh(); persist.start(file);
  const first = await h.run('ransomware'); await h.settled(first); await new Promise((r) => setTimeout(r, 2500)); // let the first incident finish so it is persisted as RESOLVED
  persist.stop(); h.fresh(); persist.start(file);
  await scen.launch('credential-compromise', { speed: 0 });
  const i = await h.until(() => [...h.cmd.incidents.values()][0]); await h.settled(i);
  await new Promise((r) => setTimeout(r, 2500)); // let the scenario's remaining steps drain so nothing leaks into the next test
  const before = { id: i.id, evidence: i.evidence.sha256, audit: h.audit.verify().length, events: h.events.all().length };
  persist.stop();
  h.cmd.reset(); h.audit.reset(); h.events.reset();               // simulate a fresh process
  const r = persist.start(file);
  assert.ok(r.audit.ok, 'audit chain verifies after reload');
  assert.equal(h.audit.verify().length >= before.audit, true);
  const back = h.cmd.incidents.get(before.id); assert.ok(back); assert.equal(back.state, 'RESOLVED'); assert.equal(back.evidence.sha256, before.evidence);
  assert.ok(h.events.all().length >= before.events - 1);
  persist.stop();
});

test('an incident that was mid-workflow is flagged for a human, never silently resumed', async () => {
  const file = tmp(); h.fresh('watch'); h.cmd.settings.autopilot = false; persist.start(file);
  await scen.launch('credential-compromise', { speed: 0 });
  await h.until(() => h.cmd.pendingFor().length > 0); const id = [...h.cmd.incidents.keys()][0];
  persist.stop();                                                   // "crash" while an approval is pending
  h.cmd.reset(); h.audit.reset(); h.events.reset();
  const r = persist.start(file); assert.equal(r.interrupted, 1);
  const inc = h.cmd.incidents.get(id); assert.equal(inc.status, 'Needs Attention'); assert.equal(inc.interrupted, true);
  assert.ok(inc.containment.filter((a) => a.tier === 'approval').every((a) => a.status === 'blocked'), 'pending approvals are cancelled, not auto-run');
  assert.ok(h.audit._chain.some((e) => e.action === 'INCIDENT_INTERRUPTED_BY_RESTART'));
  persist.stop();
});

test('tampering with the stored audit log is detected on load', async () => {
  const file = tmp(); h.fresh(); persist.start(file); await scen.launch('benign-travel', { speed: 0 }); const i = await h.until(() => [...h.cmd.incidents.values()][0]); await h.settled(i); persist.stop();
  const { DatabaseSync } = require('node:sqlite'); const d = new DatabaseSync(file);
  const row = d.prepare('SELECT seq,json FROM audit WHERE seq=3').get(); const j = JSON.parse(row.json); j.detail = { forged: true }; d.prepare('UPDATE audit SET json=? WHERE seq=3').run(JSON.stringify(j)); d.close();
  h.cmd.reset(); h.audit.reset(); const r = persist.start(file); assert.equal(r.audit.ok, false); assert.equal(r.audit.brokenAt, 3); persist.stop();
});

test('backup produces a restorable copy', async () => {
  const file = tmp(); h.fresh(); persist.start(file); await scen.launch('benign-travel', { speed: 0 }); await h.until(() => h.cmd.incidents.size); 
  const dest = file + '.bak'; require('../server/core/db').api.backup(dest); assert.ok(fs.statSync(dest).size > 0); persist.stop();
  h.cmd.reset(); h.audit.reset(); h.events.reset(); const r = persist.start(dest); assert.ok(r.audit.ok && r.restored >= 1); persist.stop();
});

test('an interrupted incident can be resumed deliberately and then completes', async () => {
  const file = tmp(); h.fresh('watch'); h.cmd.settings.autopilot = false; persist.start(file);
  await scen.launch('credential-compromise', { speed: 0 });
  await h.until(() => h.cmd.pendingFor().length > 0); const id = [...h.cmd.incidents.keys()][0];
  persist.stop(); h.cmd.reset(); h.audit.reset(); h.events.reset();
  persist.start(file); const inc = h.cmd.incidents.get(id); assert.equal(inc.interrupted, true);
  h.cmd.settings.autopilot = true; h.cmd.resume(id, 'admin');
  await h.until(() => inc.state === 'RESOLVED' || inc.status === 'Needs Attention' && !inc.interrupted, 30000);
  assert.equal(inc.interrupted, false); assert.ok(h.audit._chain.some((e) => e.action === 'INCIDENT_RESUMED'));
  await new Promise((r) => setTimeout(r, 1500)); persist.stop();
});
