'use strict';
// RECOVERY REHEARSAL ENGINE. Simulates "what if X were compromised?" against the live graph WITHOUT changing anything:
// affected services -> dependents -> recovery plan -> readiness checks -> missing requirements -> estimate -> score + verdict.
// The only outbound calls are read-only (e.g. listing Supabase backups).
const crypto = require('crypto');
const db = require('../core/db'); const audit = require('../core/audit');
const graph = require('./graph'); const blast = require('./blast'); const verify = require('./verify'); const col = require('../collectors');

const LINKS = {
  supabase: 'https://supabase.com/dashboard/project/_/settings/api', vercel: 'https://vercel.com/dashboard', render: 'https://dashboard.render.com/', netlify: 'https://app.netlify.com/', heroku: 'https://dashboard.heroku.com/apps', github: 'https://github.com/settings/tokens',
};
const REDEPLOY_MIN = { render: 4, vercel: 2, netlify: 2, heroku: 1 }; const BACKUP_FRESH_DAYS = 30;
const SCENARIOS = {
  credential: 'A credential or API key is compromised (e.g. a Supabase service key)',
  repo: 'A repository or its access token is compromised (malicious commit / leaked deploy key)',
  provider: 'A provider account is taken over (every project on it)',
};
const kvGet = (k, d) => db.kvGet(k, d);

function attestBackup(nodeId, note, by) {
  const n = graph.node(nodeId); if (!n) throw new Error('unknown node'); const m = kvGet('rz_backups', {}); m[nodeId] = { at: new Date().toISOString(), by, note: String(note || '').slice(0, 200) };
  db.kvSet('rz_backups', m); audit.log(by, 'RZ_BACKUP_ATTESTED', { node: nodeId, note: m[nodeId].note }); return m[nodeId];
}
async function backupStatus(n) {
  if (n.provider === 'supabase' && n.meta?.collector) {
    const c = col.tokenFor(n.meta.collector);
    if (c) try { const d = await col.http(`${col.BASE.supabase()}/projects/${n.meta.externalId}/database/backups`, { token: c.token }); const list = (d.backups || []).filter((b) => !b.status || /complete/i.test(b.status)); const latest = list.map((b) => Date.parse(b.inserted_at)).filter(Boolean).sort((a, b) => b - a)[0];
      if (latest || d.pitr_enabled) return { ok: true, verified: true, detail: d.pitr_enabled ? 'Point-in-time recovery is enabled' + (latest ? '; latest backup ' + new Date(latest).toISOString().slice(0, 10) : '') : `latest completed backup ${new Date(latest).toISOString().slice(0, 10)} (${list.length} available)` };
      return { ok: false, verified: true, detail: 'The Supabase API reports no completed backups for this project' }; } catch (e) { /* fall through to attestation */ }
  }
  const a = kvGet('rz_backups', {})[n.id];
  if (a && Date.now() - Date.parse(a.at) < BACKUP_FRESH_DAYS * 864e5) return { ok: true, verified: false, detail: `Admin attested a backup on ${a.at.slice(0, 10)}${a.note ? ' (' + a.note + ')' : ''}; PHOENIX X could not verify it` };
  return { ok: false, verified: false, detail: 'No verifiable backup and no recent admin attestation' };
}
function targetsFor(scenario, target) {
  if (scenario === 'provider') { const p = String(target || '').toLowerCase(); return graph.nodes().filter((n) => n.provider === p && n.type !== 'secret').map((n) => n.id); }
  const hit = graph.find(target); if (!hit.length) throw new Error('no node matches "' + target + '"; run discovery or add it on the Map'); return [hit[0].id];
}
function suggest() {
  const N = graph.nodes(), out = [];
  for (const n of N.filter((x) => x.type === 'database')) out.push({ scenario: 'credential', target: n.id, label: `${n.name} API key compromised` });
  for (const n of N.filter((x) => x.type === 'repo')) out.push({ scenario: 'repo', target: n.id, label: `${n.name} repository compromised` });
  for (const p of [...new Set(N.filter((x) => x.provider && ['vercel', 'render', 'netlify', 'heroku', 'supabase'].includes(x.provider)).map((x) => x.provider))]) out.push({ scenario: 'provider', target: p, label: `${p} account takeover` });
  return out;
}
// Build ordered recovery steps from a blast radius. kind: auto (PHOENIX X can execute after approval) | manual (needs a human at the provider).
function buildSteps(origins, b, writeOk) {
  const steps = [], O = origins.map((i) => graph.node(i)), link = (p) => LINKS[p] || null;
  for (const o of O.filter((x) => x.type !== 'repo')) steps.push({ id: 's' + (steps.length + 1), phase: 'contain', title: `Revoke / rotate the compromised credential for ${o.name}`, kind: 'manual', provider: o.provider, link: link(o.provider), minutes: 3, change: `Old ${o.name} credential stops working`, risk: 'Anything still using the old credential fails until step 2 and the redeploy are done', reverse: 'Re-issue is not possible for most providers; create a new key instead', verifyBy: 'old credential rejected' });
  for (const o of O.filter((x) => x.type === 'repo')) steps.push({ id: 's' + (steps.length + 1), phase: 'contain', title: `Rotate tokens and review recent commits for ${o.name}`, kind: 'manual', provider: 'github', link: link('github'), minutes: 5, change: 'Access tokens replaced; suspicious commits reverted', risk: 'CI/CD using the old token fails until updated', reverse: 'Re-add the previous collaborator/token if rotation was a mistake', verifyBy: 'old credential rejected; build succeeds' });
  const secrets = b.affected.filter((a) => a.type === 'secret');
  for (const s of secrets) { const n = graph.node(s.id), dep = b.affected.find((a) => a.type === 'deployment' && s.path.includes(a.id)) || graph.dependents(s.id).map((d) => d.node).find((d) => d.type === 'deployment'); steps.push({ id: 's' + (steps.length + 1), phase: 'replace', title: `Set the new value of ${n.meta?.variable || n.name} on ${dep?.name || n.provider}`, kind: 'manual', provider: n.provider, link: link(n.provider), minutes: 2, change: `${n.meta?.variable || n.name} updated (value never passes through PHOENIX X)`, risk: s.confidence === 'verified' ? 'Low' : 'Link inferred from the variable name: confirm this variable is really affected', reverse: 'Restore the previous value from your secret manager', verifyBy: 'new credential works' }); }
  for (const d of b.needsRedeploy) { const nd = graph.node(d.id); const can = writeOk(nd) && REDEPLOY_MIN[nd.provider]; steps.push({ id: 's' + (steps.length + 1), phase: 'redeploy', title: `${nd.provider === 'heroku' ? 'Restart' : 'Redeploy'} ${nd.name}`, kind: can ? 'auto' : 'manual', provider: nd.provider, link: link(nd.provider), node: nd.id, minutes: REDEPLOY_MIN[nd.provider] || 3, change: `New instance of ${nd.name} starts with the replaced credentials`, risk: `Brief interruption while ${nd.name} restarts (about ${REDEPLOY_MIN[nd.provider] || 3} min)`, reverse: nd.provider === 'heroku' ? 'Restart is idempotent' : 'Roll back to the previous deployment (recorded before the action)', verifyBy: 'endpoint health' }); }
  steps.push({ id: 's' + (steps.length + 1), phase: 'verify', title: 'Run recovery verification (health, auth, old credential rejected)', kind: 'auto', minutes: 1, change: 'None (read-only probes)', risk: 'None', reverse: 'n/a', verifyBy: 'verification engine' });
  return steps;
}
async function run({ scenario = 'credential', target, by = 'system' }) {
  if (!SCENARIOS[scenario]) throw new Error('scenario must be one of ' + Object.keys(SCENARIOS).join(', '));
  const origins = targetsFor(scenario, target), b = blast.compute(origins);
  const writeOk = (n) => { const c = n.meta?.collector && col.tokenFor(n.meta.collector); return !!(c && c.write); };
  const steps = buildSteps(origins, b, writeOk), checks = [];
  const add = (id, label, status, detail, { weight = 10, blocking = false, fix = null } = {}) => checks.push({ id, label, status, detail, weight, blocking, fix });
  const involved = [...origins.map((i) => graph.node(i)), ...b.affected.map((a) => graph.node(a.id))].filter(Boolean);
  const deploys = involved.filter((n) => n.type === 'deployment'), dbs = involved.filter((n) => n.type === 'database');
  // 1 graph confidence
  const conf = b.counts.total ? b.counts.verified / b.counts.total : 0;
  add('map', 'Dependencies are known', !b.counts.total ? 'fail' : conf >= 0.8 ? 'pass' : 'warn', !b.counts.total ? 'Nothing depends on this node in the map. Either nothing is affected or discovery is incomplete.' : `${b.counts.verified} of ${b.counts.total} affected items are verified by a provider API; ${b.counts.inferred} are inferred from names`, { weight: 15, blocking: !b.counts.total, fix: 'Connect every provider you use, run discovery, and add missing links on the Map.' });
  // 2 provider access
  const noAccess = deploys.filter((n) => !(n.meta?.collector && col.tokenFor(n.meta.collector)));
  add('access', 'PHOENIX X can see every affected service', noAccess.length ? 'warn' : 'pass', noAccess.length ? `No read connection for: ${noAccess.map((n) => n.name).join(', ')}` : `${deploys.length} service(s) connected read-only`, { weight: 10, fix: 'Connect the provider on the Connect page.' });
  // 3 replacement credentials
  const secs = b.affected.filter((a) => a.type === 'secret'), unverifiedSecs = secs.filter((s) => s.confidence !== 'verified');
  add('replace', 'Replacement credentials can be configured', !secs.length ? 'warn' : unverifiedSecs.length ? 'warn' : 'pass', !secs.length ? 'No environment variable holding this credential was found: the new key may have nowhere to go' : `${secs.length} variable(s) located${unverifiedSecs.length ? `; ${unverifiedSecs.length} only inferred` : ' and confirmed'}. A human sets the new value at the provider (links are in the plan)`, { weight: 15, fix: 'Run discovery so variable names are read from the provider.' });
  // 4 redeploy capability
  const manualRedeploy = deploys.filter((n) => !writeOk(n) || !REDEPLOY_MIN[n.provider]);
  add('redeploy', 'Affected services can be redeployed', !deploys.length ? 'warn' : manualRedeploy.length ? 'warn' : 'pass', !deploys.length ? 'No deployable service is affected' : manualRedeploy.length ? `Redeploy by PHOENIX X is not enabled for: ${manualRedeploy.map((n) => n.name).join(', ')} (a human must redeploy)` : `${deploys.length} service(s) can be redeployed by PHOENIX X after approval`, { weight: 10, fix: 'Enable write access on that connection (Connect page) with a token that is allowed to deploy.' });
  // 5 backups
  if (dbs.length) { const bs = await Promise.all(dbs.map(async (d) => [d, await backupStatus(d)])); const bad = bs.filter(([, s]) => !s.ok), unver = bs.filter(([, s]) => s.ok && !s.verified);
    add('backup', 'A restorable backup exists', bad.length ? 'fail' : unver.length ? 'warn' : 'pass', bs.map(([d, s]) => `${d.name}: ${s.detail}`).join('; '), { weight: 20, blocking: bad.length > 0, fix: 'Enable backups at the database provider, or record a verified backup (Rehearse page → Record backup).' }); }
  else add('backup', 'A restorable backup exists', 'pass', 'No database is affected in this scenario', { weight: 5 });
  // 6 verification coverage
  const vc = verify.list(); const uncovered = [...deploys, ...dbs].filter((n) => !vc.some((c) => c.node === n.id) && !vc.some((c) => !c.node));
  add('verify', 'Recovery can be proven with real tests', !vc.length ? 'fail' : uncovered.length ? 'warn' : 'pass', !vc.length ? 'No verification checks are defined: recovery could not be proven' : uncovered.length ? `No check covers: ${uncovered.map((n) => n.name).join(', ')}` : `${vc.length} check(s) cover the affected services`, { weight: 20, blocking: !vc.length, fix: 'Add checks on the Verify page (health endpoint, auth, old key rejected).' });
  const cred = scenario === 'credential' || scenario === 'provider'; const hasReject = vc.some((c) => c.type === 'rejects_credential');
  if (cred) add('reject', 'Old credential revocation can be tested', hasReject ? 'pass' : 'warn', hasReject ? 'A check confirms the old credential is refused' : 'No "old credential rejected" check: you could not prove the leaked key is dead', { weight: 10, fix: 'Add a "rejects_credential" check with the old key (stored encrypted).' });
  // 7 approver
  add('approver', 'An admin can approve execution', 'pass', 'Execution always needs an admin approval after a preview', { weight: 5 });
  const pts = { pass: 1, warn: 0.5, fail: 0 }, tw = checks.reduce((s, c) => s + c.weight, 0), score = Math.round(checks.reduce((s, c) => s + c.weight * pts[c.status], 0) / tw * 100);
  const blockers = checks.filter((c) => c.blocking && c.status === 'fail'), verdict = blockers.length ? 'NOT_READY' : score >= 85 ? 'READY' : 'PARTIALLY_READY';
  const humanMin = steps.filter((s) => s.kind === 'manual').reduce((m, s) => m + s.minutes, 0), autoMin = steps.filter((s) => s.kind === 'auto').reduce((m, s) => m + s.minutes, 0);
  const interruption = deploys.map((n) => ({ service: n.name, provider: n.provider, expectedMinutes: REDEPLOY_MIN[n.provider] || 3, note: writeOk(n) ? 'restart by PHOENIX X after approval' : 'restart by a human' }));
  const rep = { id: 'reh-' + crypto.randomBytes(4).toString('hex'), at: new Date().toISOString(), scenario, scenarioLabel: SCENARIOS[scenario], target: target || null, origins: b.origins, simulated: true, nothingChanged: true,
    blast: b, plan: steps, checks, missing: checks.filter((c) => c.status !== 'pass').map((c) => ({ id: c.id, label: c.label, severity: c.blocking && c.status === 'fail' ? 'blocking' : c.status === 'fail' ? 'high' : 'medium', detail: c.detail, fix: c.fix })),
    estimate: { steps: steps.length, humanSteps: steps.filter((s) => s.kind === 'manual').length, automatedSteps: steps.filter((s) => s.kind === 'auto').length, minutes: humanMin + autoMin, humanMinutes: humanMin, interruptions: interruption },
    score, verdict, blockers: blockers.map((c) => c.label) };
  db.get().prepare('insert into rz_runs(id,kind,ref,status,result,by,at) values(?,?,?,?,?,?,?)').run(rep.id, 'rehearsal', target || scenario, verdict, JSON.stringify(rep), by, rep.at);
  audit.log(by, 'RZ_REHEARSED', { id: rep.id, scenario, target, score, verdict }); return rep;
}
const history = (limit = 20) => db.get().prepare("select result from rz_runs where kind='rehearsal' order by at desc limit ?").all(limit).map((r) => { const x = JSON.parse(r.result); return { id: x.id, at: x.at, scenario: x.scenario, scenarioLabel: x.scenarioLabel, target: x.target, score: x.score, verdict: x.verdict, affected: x.blast.counts.total }; });
const get = (id) => { const r = db.get().prepare("select result from rz_runs where id=? and kind='rehearsal'").get(id); return r ? JSON.parse(r.result) : null; };
module.exports = { SCENARIOS, run, suggest, history, get, attestBackup, buildSteps, REDEPLOY_MIN, LINKS };
