'use strict';
// SAFE RECOVERY EXECUTION ENGINE. Nothing runs without: preview -> admin approval -> execution -> automatic verification.
// The preview states what changes, which services are affected, what could go wrong, how to reverse it and what will verify it.
// Real controlled actions: redeploy/restart of an affected service (Render, Vercel, Netlify, Heroku) with a recorded rollback target.
// Credential revocation and setting new secret values stay with a human (links provided): PHOENIX X never sees new secrets.
// Provider calls honour PHOENIX_CONNECTOR_DRYRUN (default ON) and the per-connection "write access" switch.
const crypto = require('crypto');
const db = require('../core/db'); const audit = require('../core/audit'); const config = require('../core/config');
const graph = require('./graph'); const rehearse = require('./rehearse'); const verify = require('./verify'); const col = require('../collectors');

const q = (c) => (c.config.teamId ? `?teamId=${encodeURIComponent(c.config.teamId)}` : '');
const act = (c, path, method, body) => col.http(col.BASE[c.platform]() + path, { token: c.token, method, body, text: true, headers: c.platform === 'heroku' ? { accept: 'application/vnd.heroku+json; version=3' } : {} });
const jget = (c, path) => col.http(col.BASE[c.platform]() + path, { token: c.token, headers: c.platform === 'heroku' ? { accept: 'application/vnd.heroku+json; version=3' } : {} });
const ADAPTER = {
  render: { prev: async (c, id) => { const d = await jget(c, `/services/${id}/deploys?limit=1`); return ((d[0] || {}).deploy || d[0] || {}).id || null; }, go: (c, id) => act(c, `/services/${id}/deploys`, 'POST', { clearCache: 'do_not_clear' }), back: (c, id, prev) => act(c, `/services/${id}/rollback`, 'POST', { deployId: prev }) },
  vercel: { prev: async (c, id) => { const d = await jget(c, `/v6/deployments?projectId=${encodeURIComponent(id)}&target=production&state=READY&limit=1${q(c) ? '&' + q(c).slice(1) : ''}`); return d.deployments?.[0]?.uid || null; }, go: (c, id, n, prev) => { if (!prev) throw new Error('no previous production deployment to redeploy from'); return act(c, `/v13/deployments${q(c)}`, 'POST', { name: n.name, deploymentId: prev, target: 'production' }); }, back: (c, id, prev) => act(c, `/v9/projects/${encodeURIComponent(id)}/rollback/${encodeURIComponent(prev)}${q(c)}`, 'POST') },
  netlify: { prev: async (c, id) => { const d = await jget(c, `/sites/${id}/deploys?per_page=1`); return d[0]?.id || null; }, go: (c, id) => act(c, `/sites/${id}/builds`, 'POST', {}), back: (c, id, prev) => act(c, `/sites/${id}/deploys/${prev}/restore`, 'POST') },
  heroku: { prev: async () => null, go: (c, id) => act(c, `/apps/${id}/dynos`, 'DELETE'), back: null },
};
const store = (p) => db.get().prepare('insert into rz_runs(id,kind,ref,status,result,by,at) values(?,?,?,?,?,?,?) on conflict(id) do update set status=excluded.status, result=excluded.result').run(p.id, 'plan', p.ref, p.status, JSON.stringify(p), p.by, p.at);
const get = (id) => { const r = db.get().prepare("select result from rz_runs where id=? and kind='plan'").get(id); return r ? JSON.parse(r.result) : null; };
const list = (limit = 20) => db.get().prepare("select result from rz_runs where kind='plan' order by at desc limit ?").all(limit).map((r) => { const p = JSON.parse(r.result); return { id: p.id, at: p.at, status: p.status, scenario: p.scenario, target: p.target, steps: p.steps.length, done: p.steps.filter((s) => ['done', 'skipped', 'dry_run'].includes(s.status)).length, dryRun: p.dryRun }; });

function create({ rehearsalId, scenario, target }, by) {
  return (async () => {
    const reh = rehearsalId ? rehearse.get(rehearsalId) : await rehearse.run({ scenario, target, by });
    if (!reh) throw new Error('rehearsal not found');
    const p = { id: 'plan-' + crypto.randomBytes(4).toString('hex'), at: new Date().toISOString(), by, status: 'preview', ref: reh.id, rehearsal: reh.id, scenario: reh.scenario, target: reh.target, readiness: { score: reh.score, verdict: reh.verdict }, dryRun: !!config.connectorDryRun,
      steps: reh.plan.map((s) => ({ ...s, status: 'pending', log: [] })),
      preview: { changes: [...new Set(reh.plan.map((s) => s.change))], affectedServices: reh.blast.connectedDeployments, affectedAll: reh.blast.affected.map((a) => `${a.type}:${a.name} (${a.confidence})`), risks: [...new Set(reh.plan.map((s) => s.risk))].filter((x) => x && x !== 'None' && x !== 'Low'), reversal: [...new Set(reh.plan.map((s) => s.reverse))].filter((x) => x && x !== 'n/a'), verification: verify.list().map((c) => `${c.name} [${c.label}]`), blockers: reh.blockers, estimate: reh.estimate } };
    store(p); audit.log(by, 'RZ_PLAN_CREATED', { id: p.id, scenario: p.scenario, target: p.target }); return p;
  })();
}
function approve(id, by) { const p = get(id); if (!p) throw new Error('plan not found'); if (p.status !== 'preview') throw new Error('plan is already ' + p.status); if (p.preview.blockers.length) throw new Error('blocked by readiness gaps: ' + p.preview.blockers.join('; ')); p.status = 'approved'; p.approvedBy = by; p.approvedAt = new Date().toISOString(); store(p); audit.log(by, 'RZ_PLAN_APPROVED', { id }); return p; }
function reject(id, by) { const p = get(id); if (!p) throw new Error('plan not found'); p.status = 'rejected'; store(p); audit.log(by, 'RZ_PLAN_REJECTED', { id }); return p; }

const finished = (s) => ['done', 'skipped', 'dry_run'].includes(s.status);
async function runAuto(p, s, by) {
  if (s.phase === 'verify') { const nodes = p.steps.filter((x) => x.node).map((x) => x.node); const rep = await verify.run({ nodes: nodes.length ? nodes : null, ref: p.id, by }); s.verification = { id: rep.id, verdict: rep.verdict, passed: rep.passed, failed: rep.failed, sha256: rep.sha256 }; s.status = rep.verdict === 'FAILED' ? 'failed' : 'done'; s.log.push(`verification ${rep.verdict}: ${rep.passed}/${rep.total} passed`); return; }
  const n = graph.node(s.node), conn = n?.meta?.collector && col.tokenFor(n.meta.collector), ad = ADAPTER[s.provider];
  if (!n || !conn || !ad) { s.status = 'failed'; s.log.push('no usable connection for this service'); return; }
  if (!conn.write) { s.status = 'failed'; s.log.push('write access is not enabled on this connection'); return; }
  try {
    s.prev = await ad.prev(conn, n.meta.externalId).catch(() => null);
    if (config.connectorDryRun) { s.status = 'dry_run'; s.log.push(`DRY-RUN: would ${s.title.toLowerCase()} via ${s.provider}. Nothing was changed. (set PHOENIX_CONNECTOR_DRYRUN=off to act)`); audit.log(by, 'RZ_STEP_DRYRUN', { plan: p.id, step: s.id, node: s.node }); return; }
    await ad.go(conn, n.meta.externalId, n, s.prev); s.status = 'done'; s.executedAt = new Date().toISOString(); s.log.push(`${s.title}: accepted by ${s.provider}` + (s.prev ? `; rollback target ${s.prev}` : '')); audit.log(by, 'RZ_STEP_EXECUTED', { plan: p.id, step: s.id, node: s.node, prev: s.prev });
  } catch (e) { s.status = 'failed'; s.log.push('failed: ' + String(e.message).slice(0, 160)); audit.log(by, 'RZ_STEP_FAILED', { plan: p.id, step: s.id, error: e.message }); }
}
// Run every auto step whose earlier steps are finished. Manual steps wait for a human (markStep).
async function advance(p, by) {
  for (const s of p.steps) {
    if (finished(s)) continue; if (s.status === 'failed') break;
    if (s.kind === 'manual') { s.status = 'pending'; break; }
    await runAuto(p, s, by); if (s.status === 'failed') break;
  }
  const open = p.steps.filter((s) => !finished(s));
  if (p.steps.some((s) => s.status === 'failed')) p.status = p.steps.find((s) => s.phase === 'verify')?.status === 'failed' ? 'verification_failed' : 'needs_attention';
  else if (!open.length) p.status = p.steps.some((s) => s.status === 'dry_run') ? 'dry_run_complete' : 'recovered_verified';
  else p.status = 'waiting_on_human';
  if (['recovered_verified', 'dry_run_complete', 'verification_failed'].includes(p.status)) p.completedAt = new Date().toISOString();
  store(p); return p;
}
async function execute(id, by) { const p = get(id); if (!p) throw new Error('plan not found'); if (!['approved', 'waiting_on_human', 'needs_attention'].includes(p.status)) throw new Error(p.status === 'preview' ? 'plan must be approved by an admin first' : 'plan is ' + p.status); p.status = 'executing'; for (const s of p.steps) if (s.status === 'failed') { s.status = 'pending'; s.log.push('retry'); } audit.log(by, 'RZ_PLAN_EXECUTING', { id }); return advance(p, by); }
async function markStep(id, stepId, by, state = 'done') {
  const p = get(id); if (!p) throw new Error('plan not found'); if (!['waiting_on_human', 'approved', 'needs_attention', 'executing'].includes(p.status)) throw new Error('plan is ' + p.status + '; approve and execute it first');
  const s = p.steps.find((x) => x.id === stepId); if (!s) throw new Error('step not found'); if (s.kind !== 'manual') throw new Error('this step is run by PHOENIX X'); if (!['done', 'skipped'].includes(state)) throw new Error('state must be done or skipped');
  if (state === 'skipped' && s.phase === 'contain') throw new Error('containing the compromised credential cannot be skipped');
  s.status = state; s.by = by; s.log.push(`${state} by ${by}`); audit.log(by, 'RZ_STEP_' + state.toUpperCase(), { plan: id, step: stepId }); return advance(p, by);
}
async function undoStep(id, stepId, by) {
  const p = get(id); const s = p?.steps.find((x) => x.id === stepId); if (!s) throw new Error('step not found'); if (s.status !== 'done' || !s.node) throw new Error('only executed redeploy steps can be rolled back');
  const n = graph.node(s.node), conn = col.tokenFor(n.meta.collector), ad = ADAPTER[s.provider]; if (!ad.back || !s.prev) throw new Error('no rollback target was recorded for this step (restart is idempotent; nothing to undo)');
  if (!conn?.write) throw new Error('write access is not enabled on this connection'); await ad.back(conn, n.meta.externalId, s.prev); s.status = 'rolled_back'; s.log.push(`rolled back to ${s.prev} by ${by}`); p.status = 'needs_attention'; store(p); audit.log(by, 'RZ_STEP_ROLLED_BACK', { plan: id, step: stepId, prev: s.prev }); return p;
}
module.exports = { create, approve, reject, execute, markStep, undoStep, get, list, ADAPTER };
