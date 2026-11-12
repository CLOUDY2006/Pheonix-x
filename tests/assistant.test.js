'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers');
const cmd = require('../server/agents/commander');
const assistant = require('../server/agents/assistant');
const auth = require('../server/core/auth');
const autonomy = require('../server/core/autonomy');
const admin = { sub: 'admin', role: 'admin' }, analyst = { sub: 'analyst', role: 'analyst' }, viewer = { sub: 'viewer', role: 'viewer' };

test('chat asks "which sam?" and resolves by number, by name, or by the IP address of the incident', async () => {
  h.fresh(); assistant.reset();
  const mk = (id, user, ip) => ({ id, incidentId: 'INC-T' + id, type: 'disable_account', target: { user }, description: `Suspend ${user}`, aiAuto: true });
  cmd.incidents.set('INC-Ta1', { id: 'INC-Ta1', title: 'a', alerts: [{ evidence: 'from 203.0.113.9' }], containment: [] }); cmd.incidents.set('INC-Ta2', { id: 'INC-Ta2', title: 'b', alerts: [{ evidence: 'from 198.51.100.4' }], containment: [] });
  const list = [mk('a1', 'sam.lee'), mk('a2', 'sam.patel'), mk('a3', 'maria.g')]; const undone = [];
  const oc = cmd.containments, ou = cmd.undoAction; cmd.containments = () => list.filter((x) => !undone.includes(x.id)); cmd.undoAction = async (id) => { undone.push(id); };
  try {
    let r = await assistant.handle(analyst, 'unblock sam'); assert.match(r.reply, /2\*\* matches/); assert.equal(r.choices.length, 3); assert.equal(undone.length, 0);
    r = await assistant.handle(analyst, '2'); assert.deepEqual(undone, ['a2']); assert.match(r.reply, /Unblocked/);
    list.push(mk('a4', 'sam.kim')); cmd.incidents.set('INC-Ta4', { id: 'INC-Ta4', title: 'c', alerts: [{ evidence: '192.0.2.77' }], containment: [] });
    r = await assistant.handle(analyst, 'unblock sam'); assert.match(r.reply, /2\*\* matches/);
    r = await assistant.handle(analyst, 'the one from 203.0.113.9'); assert.deepEqual(undone, ['a2', 'a1'], 'resolved through the incident IP');
    r = await assistant.handle(analyst, 'unblock nobody'); assert.match(r.reply, /couldn't find/);
    r = await assistant.handle(analyst, 'unblock maria.g'); assert.deepEqual(undone.at(-1), 'a3', 'single match runs straight away');
    assert.match((await assistant.handle(viewer, 'unblock sam.kim')).reply, /analyst/, 'role enforced');
  } finally { cmd.containments = oc; cmd.undoAction = ou; for (const k of ['INC-Ta1', 'INC-Ta2', 'INC-Ta4']) cmd.incidents.delete(k); }
});

test('chat runs the real thing end to end: status, blocks, unblock by IP, mode change (admin only)', async () => {
  const inc = await h.run('credential-compromise', { mode: 'balanced' }); await h.settled(inc); assistant.reset();
  assert.match((await assistant.handle(viewer, 'status')).reply, /Open incidents|All quiet/);
  const blocks = await assistant.handle(viewer, "what's blocked?"); assert.match(blocks.reply, /active block/);
  const ip = inc.containment.find((a) => a.type === 'block_ip' && a.status === 'executed').target.ip;
  const r = await assistant.handle(analyst, 'unblock ' + ip); assert.match(r.reply, /Unblocked/); assert.equal(h.sim.env.firewall.blockedIPs.has(ip), false);
  assert.match((await assistant.handle(analyst, 'set mode to full')).reply, /admin/); assert.equal(autonomy.getMode(), 'balanced');
  assert.match((await assistant.handle(admin, 'set mode to full')).reply, /Full AI/); assert.equal(autonomy.getMode(), 'full');
  assert.match((await assistant.handle(viewer, 'gibberish xyz')).reply, /didn't understand/);
});

test('Watch mode: "allow" in chat lets the AI execute the pending action; "disallow" keeps it off', async () => {
  h.fresh('watch'); cmd.settings.autopilot = false; assistant.reset();
  await require('../server/scenarios').launch('credential-compromise', { speed: 0 }); await h.until(() => cmd.pendingFor().length >= 2);
  const n = cmd.pendingFor().length; const q = await assistant.handle(admin, 'what needs me'); assert.match(q.reply, /waiting for your OK/);
  let r = await assistant.handle(admin, 'allow'); assert.match(r.reply, /matches/, 'several pending: it asks which');
  r = await assistant.handle(admin, '1'); assert.match(r.reply, /Allowed/); assert.equal(cmd.pendingFor().length, n - 1);
  r = await assistant.handle(admin, 'disallow all'); assert.match(r.reply, /Disallowed/); await h.until(() => cmd.pendingFor().length === 0);
  cmd.setAutopilot(true); await h.until(() => [...cmd.incidents.values()][0].verification, 15000);
});

test('chat can rotate an ingest key: new key works, old key is dead', async () => {
  assistant.reset(); const k = auth.createKey({ name: 'vercel-prod', format: 'vercel' }, 'admin');
  const r = await assistant.handle(admin, 'rotate key vercel'); const nk = /`(phx_[\w-]+)`/.exec(r.reply)?.[1]; assert.ok(nk, r.reply);
  assert.equal(auth.verifyKey(k.key), null); assert.equal(auth.verifyKey(nk).name, 'vercel-prod'); assert.match((await assistant.handle(analyst, 'rotate key vercel')).reply, /admin/);
});

test('recovery steps: optional ones can be skipped, required ones cannot, and the AI step is gated by Allow in Watch mode', async () => {
  h.fresh('watch'); const mkInc = () => { const inc = { id: 'INC-S1', state: 'RECOVERING', alerts: [], containment: [], recovery: { readiness: [], tasks: [] }, workflow: {}, messages: [] }; return inc; };
  const inc = mkInc(); const T = inc.recovery.tasks; T.push({ id: 't1', title: 'snapshot', kind: 'forensic_capture', owner: 'human', status: 'pending', optional: true }, { id: 't2', title: 'reset pw', kind: 'reset_credentials', owner: 'human', status: 'pending', critical: true, dependsOn: ['t1'] }, { id: 't3', title: 're-enable', kind: 'reenable_account', owner: 'RECOVERY', gate: 'allow', status: 'pending', dependsOn: ['t2'] });
  cmd.incidents.set(inc.id, inc);
  try {
    await assert.rejects(() => cmd.skipTask(inc.id, 't2', 'u'), /required/); await assert.rejects(() => cmd.completeTask(inc.id, 't2', 'u'), /earlier step/);
    await cmd.skipTask(inc.id, 't1', 'u'); assert.equal(T[0].status, 'skipped');
    await cmd.completeTask(inc.id, 't2', 'u'); assert.equal(T[1].status, 'done');
    await cmd.skipTask(inc.id, 't3', 'u'); assert.equal(T[2].status, 'skipped', 'Disallow leaves the block in place');
  } finally { cmd.incidents.delete(inc.id); }
});
