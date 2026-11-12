'use strict';
// RECOVERY — System Recovery Agent. Works ONLY against the simulated backup/restore environment.
// It never performs real destructive file operations: "restore" copies a content hash inside the in-memory sim.
const { uid, sha256 } = require('../core/util');
const audit = require('../core/audit');
const sim = require('../sim/enterprise');
const guardian = require('./guardian');
const { validate, SPECS } = require('../core/schema');
const cfg = require('../core/config');
const autonomy = require('../core/autonomy');
const connectors = require('../connectors');

function readiness(incident, inv) {
  const hosts = [...new Set(inv.affectedAssets.filter((a) => a.type === 'host').map((a) => a.id))];
  const impacted = (h) => inv.affectedAssets.find((a) => a.id === h)?.status === 'confirmed-impacted';
  const firstTs = inv.timeline.find((t) => t.suspicious)?.ts || incident.createdAt;
  return hosts.map((h) => {
    const bks = sim.env.backups[h] || [];
    const good = bks.filter((b) => b.verified && new Date(b.ts) < new Date(firstTs)).sort((a, b) => new Date(b.ts) - new Date(a.ts))[0];
    const status = good ? 'ready' : bks.length ? 'at-risk' : 'no-backup';
    return { host: h, impacted: impacted(h), status, backup: good || bks[0] || null, note: good ? `Verified${good.immutable ? ', immutable' : ''} backup ${good.id} predates the first suspicious event` : bks.length ? 'Backups exist but none is verified — restoring is risky' : 'No backup on record: manual rebuild required' };
  });
}


// Guided steps for things only a human can do (or confirm). Shown in the app; the AI continues when the step is Done or Skipped.
const META = {
  manual_action: { critical: true, how: (t) => ['Open the admin console of the affected system (identity provider, firewall or cloud).', 'Apply the change described above.', 'Come back and press Done. PHOENIX X will then verify and continue.'] },
  confirm_isolation: { critical: true, how: (t) => [`Open your EDR or cloud console and find ${t.host}.`, 'Confirm it shows as network-isolated (or isolate it now).', 'Press Done.'] },
  forensic_capture: { optional: true, how: (t) => [`Take a disk snapshot or memory image of ${t.host} with your EDR or cloud console.`, 'Store it somewhere the attacker cannot reach.', 'No tooling for this? Press Skip. The recovery continues without evidence preservation.'] },
  restore_manual: { critical: true, how: (t) => [`Rebuild ${t.host} from your last known-good verified backup or image (not one taken after the first suspicious event).`, 'If you can, take a disk snapshot first for evidence; skipping that is fine.', 'Press Done when it is rebuilt and clean. The AI then reconnects it.'] },
  clean_scan: { critical: true, how: (t) => [`Run an EDR or antivirus full scan on ${t.host}, plus a snapshot if you can.`, 'Press Done only if it came back clean. The AI then reconnects it.'] },
  reset_credentials: { critical: true, how: (t) => [`Press the link below and reset ${t.user}'s password (and re-enrol MFA).`, `While you are there, glance at ${t.user}'s mailbox forwarding rules and app grants.`, 'Then press Check. The AI verifies it with your identity provider when connected, and continues by itself.'] },
  review_account: { optional: true, how: (t) => [`Check ${t.user}'s mailbox forwarding rules, OAuth app grants and recent sent mail.`, 'Skip this if the account has no mailbox or you already checked.'] },
  rotate_cloud_keys: { critical: true, how: (t) => [`Open the cloud console for ${t.resource}.`, 'Create new access keys / secrets, update your apps, then delete the old ones.', 'Press Done.'] },
  rotate_secret: { critical: true, how: (t) => ['Open the service that issued the exposed secret (GitHub, cloud, payment provider...).', 'Revoke the exposed secret and create a new one.', 'Update it in your hosting environment variables and redeploy.', 'Press Done.'] },
  impact_assessment: { critical: true, how: () => ['Ask the data owner what data was reachable.', 'Decide with legal whether a breach notification is required (clocks can be as short as 72 hours).', 'Press Done when decided.'] },
};
// Direct links for the things only a person can do. Vendor URLs can change; they are shortcuts, not guarantees.
const L = (label, url) => ({ label, url });
function idpLinks() {
  const out = [], ok = (process.env.OKTA_URL || '').replace(/\/$/, '');
  if (ok) out.push(L('Open Okta admin', ok.replace(/\.okta\.com$/, '-admin.okta.com') + '/admin/users'));
  if (process.env.ENTRA_TENANT_ID) out.push(L('Open Microsoft Entra users', 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers'));
  if (!out.length) out.push(L('Microsoft Entra users', 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers'), L('Google Workspace users', 'https://admin.google.com/ac/users'), L('Okta admin', 'https://login.okta.com/'));
  return out;
}
const SECRET_LINKS = { github: L('GitHub tokens & keys', 'https://github.com/settings/tokens'), vercel: L('Vercel tokens', 'https://vercel.com/account/tokens'), render: L('Render API keys', 'https://dashboard.render.com/u/settings#api-keys'), heroku: L('Heroku authorizations', 'https://dashboard.heroku.com/account/applications'), netlify: L('Netlify tokens', 'https://app.netlify.com/user/applications'), cloudflare: L('Cloudflare API tokens', 'https://dash.cloudflare.com/profile/api-tokens'), aws: L('AWS IAM credentials', 'https://console.aws.amazon.com/iam/home#/security_credentials') };
function linksFor(t, incident) {
  if (t.kind === 'reset_credentials' || (t.kind === 'manual_action' && t.actionType === 'force_password_reset')) return idpLinks();
  if (t.kind === 'rotate_cloud_keys') return [SECRET_LINKS.aws, L('Google Cloud service accounts', 'https://console.cloud.google.com/iam-admin/serviceaccounts'), L('Azure app registrations', 'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade')];
  if (t.kind === 'rotate_secret') { const txt = JSON.stringify(incident?.alerts || []).toLowerCase(); const f = Object.keys(SECRET_LINKS).filter((k) => txt.includes(k)).map((k) => SECRET_LINKS[k]); return f.length ? f : [SECRET_LINKS.github, SECRET_LINKS.vercel, SECRET_LINKS.aws]; }
  return [];
}
const CHECKABLE = new Set(['reset_credentials']);
// Can the AI verify this step by itself? Returns { known, done, detail }.
async function checkTask(task, incident) {
  if (task.kind === 'reset_credentials' || (task.kind === 'manual_action' && task.actionType === 'force_password_reset')) return connectors.checkPasswordChanged(task.user, task.createdAt || incident.createdAt);
  return { known: false, done: false, detail: 'This step cannot be verified automatically; press Done when you have finished it.' };
}
// Tasks the AI performs itself (they undo containment, so in Watch mode the human must press Allow first).
const AI_UNDO = new Set(['reconnect_host', 'reenable_account']);
function decorate(tasks, incident) {
  for (const t of tasks) {
    const m = META[t.kind]; if (m) { if (m.critical) t.critical = true; if (m.optional) t.optional = true; t.how = m.how(t); }
    if (t.owner === 'human') { const ln = linksFor(t, incident); if (ln.length) t.links = ln; if (CHECKABLE.has(t.kind) || (t.kind === 'manual_action' && t.actionType === 'force_password_reset')) t.checkable = true; t.createdAt = new Date().toISOString(); }
    if (t.owner === 'human' && !t.how) t.how = ['Complete this step in your own systems, then press Done.'];
    if (AI_UNDO.has(t.kind) && t.owner === 'RECOVERY' && autonomy.getMode() === 'watch') { t.gate = 'allow'; t.how = ['The AI will do this when you press Allow. Press Disallow to leave the block in place.']; }
  }
  return tasks;
}

function plan(incident, inv, containment) {
  const ready = readiness(incident, inv), tasks = [];
  const T = (title, kind, owner, extra = {}) => { const t = { id: uid('tsk'), title, kind, owner, status: 'pending', ...extra }; tasks.push(t); return t; };
  // Real-world containment that was dry-run or had no connector: a human must apply it and confirm here.
  for (const a of containment.filter((x) => ['dry_run', 'manual_required'].includes(x.status))) T(`APPLY MANUALLY & CONFIRM: ${a.description}${a.status === 'dry_run' ? ' (connector was in dry-run)' : ''}`, 'manual_action', 'human', { actionId: a.id, actionType: a.type, ...(a.target?.user ? { user: a.target.user } : {}) });
  for (const r of ready.filter((x) => x.impacted || containment.some((a) => a.type === 'isolate_host' && a.target.host === x.host))) {
    if (cfg.isProd) { // production: PHOENIX never touches hosts itself. ONE human step per host (rebuild/scan), then the AI reconnects it.
      const rb = T(r.impacted ? `Rebuild ${r.host}${r.status === 'ready' ? ` from verified backup ${r.backup.id}` : ` (READINESS GAP: ${r.note})`}` : `Scan ${r.host} for malware`, r.impacted ? 'restore_manual' : 'clean_scan', 'human', { host: r.host, ...(r.impacted && r.status !== 'ready' ? { gap: true } : {}) });
      T(`Reconnect ${r.host} to the network (AI lifts the isolation)`, 'reconnect_host', 'RECOVERY', { host: r.host, dependsOn: [rb.id] }); continue;
    }
    const iso = T(`Confirm ${r.host} is isolated`, 'verify_isolation', 'RECOVERY', { host: r.host });
    const snap = T(`Capture forensic snapshot of ${r.host} (evidence preservation)`, 'forensic_snapshot', 'RECOVERY', { host: r.host, dependsOn: [iso.id] });
    if (r.status === 'ready' && r.impacted) {
      const rs = T(`Restore ${r.host} from verified backup ${r.backup.id} (simulated)`, 'restore_backup', 'RECOVERY', { host: r.host, backup: r.backup.id, dependsOn: [snap.id] });
      T(`Reconnect ${r.host} to network after clean-scan sign-off`, 'reconnect_host', 'human', { host: r.host, dependsOn: [rs.id] });
    } else if (r.impacted) { const mr = T(`READINESS GAP: ${r.note}. Plan manual rebuild of ${r.host}`, 'manual_rebuild', 'human', { host: r.host, dependsOn: [snap.id], gap: true }); T(`Reconnect rebuilt ${r.host} to network after clean-scan sign-off`, 'reconnect_host', 'human', { host: r.host, dependsOn: [mr.id] }); }
    else T(`Run EDR clean-scan on ${r.host}; reconnect if clean`, 'reconnect_host', 'human', { host: r.host, dependsOn: [snap.id] });
  }
  for (const u of new Set(inv.affectedAssets.filter((a) => a.type === 'user' && !/^(recipient|reporter)/.test(a.status)).map((a) => a.id))) {
    if (!cfg.isProd && !sim.env.users[u]) continue;
    if (cfg.isProd) { // production: if the AI already forced the reset (confirmed), no human step is needed at all
      const aiReset = containment.some((a) => a.type === 'force_password_reset' && a.target.user === u && a.status === 'executed' && a.result?.providerConfirmed);
      const pendingReset = tasks.find((x) => x.kind === 'manual_action' && x.actionType === 'force_password_reset' && x.user === u);
      const reset = aiReset ? null : pendingReset || T(`Reset ${u}'s password`, 'reset_credentials', 'human', { user: u });
      if (containment.some((a) => a.type === 'disable_account' && a.target.user === u && a.status === 'executed')) T(`Re-enable account ${u} (AI does this${aiReset ? ' now that the password is reset' : ' after the reset'})`, 'reenable_account', 'RECOVERY', { user: u, ...(reset ? { dependsOn: [reset.id] } : {}) });
      continue;
    }
    const reset = T(`Reset credentials and re-enrol MFA for ${u}`, 'reset_credentials', 'human', { user: u });
    T(`Review ${u}'s mailbox rules, OAuth grants and recent sent mail`, 'review_account', 'human', { user: u });
    if (containment.some((a) => a.type === 'disable_account' && a.target.user === u)) T(`Re-enable account ${u} after verification`, 'reenable_account', 'human', { user: u, dependsOn: [reset.id] });
  }
  if (incident.alerts.some((a) => /R-PLATFORM/.test(a.rule) && /secret|key|deploy_key/i.test(JSON.stringify(a.evidence || a.title || a.rule)))) T('Rotate the exposed secret / key', 'rotate_secret', 'human');
  for (const a of inv.affectedAssets.filter((x) => x.type === 'cloud')) T(`Review and rotate credentials/keys for cloud resource ${a.id}`, 'rotate_cloud_keys', 'human', { resource: a.id });
  if (incident.alerts.some((a) => ['R-MASS-DOWNLOAD', 'R-EXFIL', 'R-CLOUD-PUBLIC'].includes(a.rule))) T('Assess data-exposure impact with data owner / legal (regulatory notification clock)', 'impact_assessment', 'human');
  decorate(tasks, incident);
  const out = { incidentId: incident.id, readiness: ready, tasks };
  const v = validate(SPECS.recovery, out, 'recovery'); if (!v.ok) throw new Error(v.errors.join(';'));
  return out;
}

async function runTask(task, incident, by = 'RECOVERY') {
  const h = task.host && sim.env.hosts[task.host];
  if (task.kind === 'manual_action') { const a = incident.containment.find((x) => x.id === task.actionId); if (a) { a.status = 'executed'; a.executedAt = new Date().toISOString(); a.result = { ...(a.result || {}), provider: 'manual', manual: true, providerConfirmed: false, confirmedBy: by, detail: `Applied manually by ${by}` }; a.simulated = false; } audit.log(by, 'MANUAL_ACTION_CONFIRMED', { action: a?.description }, incident.id); task.status = 'done'; task.completedAt = new Date().toISOString(); task.completedBy = by; return; }
  if (cfg.isProd && !['reconnect_host', 'reenable_account'].includes(task.kind)) { audit.log(by, 'TASK_ATTESTED', { task: task.title }, incident.id); task.status = 'done'; task.completedAt = new Date().toISOString(); task.completedBy = by; return; }
  switch (task.kind) {
    case 'verify_isolation': if (!h?.isolated) throw new Error(`${task.host} is NOT isolated (containment was denied or failed)`); break;
    case 'forensic_snapshot': h.forensicSnapshot = sha256('forensic-' + task.host + Date.now()); audit.log(by, 'EVIDENCE_PRESERVED', { host: task.host, snapshot: h.forensicSnapshot.slice(0, 16) }, incident.id); break;
    case 'restore_backup': { if (!h.isolated) throw new Error('refusing to restore a non-isolated host'); const bk = sim.env.backups[task.host].find((b) => b.id === task.backup); h.status = 'restoring'; h.contentHash = sha256('restored-' + bk.id); h.restoredFrom = bk.id; h.status = 'restored-isolated'; h.compromised = false; audit.log(by, 'RESTORE_COMPLETED_SIMULATED', { host: task.host, backup: bk.id }, incident.id); break; }
    case 'reconnect_host': { const act = incident.containment.find((a) => a.type === 'isolate_host' && a.target.host === task.host && a.status === 'executed'); if (act) await guardian.rollback(act, incident.id, by); else if (h) { h.isolated = false; h.status = 'online'; } audit.log(by, 'RECONNECT_CONFIRMED', { host: task.host }, incident.id); break; }
    case 'reset_credentials': { const u = sim.env.users[task.user]; if (u) { u.credentialsRotated = true; u.mfa = true; } audit.log(by, 'CREDENTIALS_RESET', { user: task.user }, incident.id); break; }
    case 'reenable_account': { const act = incident.containment.find((a) => a.type === 'disable_account' && a.target.user === task.user && a.status === 'executed'); if (act) await guardian.rollback(act, incident.id, by); break; }
    default: audit.log(by, 'TASK_ACKNOWLEDGED', { task: task.title }, incident.id);
  }
  task.status = 'done'; task.completedAt = new Date().toISOString(); task.completedBy = by;
}

function verify(incident, newAlerts = 0) {
  const checks = [];
  const C = (name, pass, detail) => checks.push({ name, pass, detail });
  const live = (a) => cfg.isProd || (a.result && a.result.provider !== 'simulated-enterprise') || ['dry_run', 'manual_required'].includes(a.status);
  for (const a of incident.containment) {
    if (live(a)) { if (a.status === 'rolled_back') continue; if (['denied', 'blocked'].includes(a.status)) continue; C(`${a.description}`, a.status === 'executed' && !!(a.result?.providerConfirmed || a.result?.manual), a.status === 'executed' ? (a.result?.manual ? `applied manually by ${a.result.confirmedBy}` : `confirmed by ${a.result?.provider}`) : `${a.status}: not applied in the real world`); continue; }
    if (a.type === 'block_ip') C(`IP ${a.target.ip} blocked`, sim.env.firewall.blockedIPs.has(a.target.ip), a.status);
    if (a.type === 'isolate_host' && a.status !== 'rolled_back') C(`Host ${a.target.host} isolated`, !!sim.env.hosts[a.target.host].isolated, a.status);
    if (a.type === 'disable_account') C(`Account ${a.target.user} suspended or reset+re-enabled safely`, sim.env.users[a.target.user].status === 'suspended' || sim.env.users[a.target.user].credentialsRotated === true, a.status);
    if (a.type === 'detach_cloud_policy') C(`Policy ${a.target.policy} absent from ${a.target.role}`, !(sim.env.cloud.roles[a.target.role]?.policies || []).some((p) => p.includes(a.target.policy)), a.status);
    if (a.type === 'make_bucket_private') C(`Bucket ${a.target.bucket} private`, sim.env.cloud.buckets[a.target.bucket]?.public === false, a.status);
    if (['revoke_sessions'].includes(a.type)) C(`Sessions for ${a.target.user} revoked`, sim.env.users[a.target.user].sessions.length === 0, a.status);
  }
  const denied = incident.containment.filter((a) => ['denied', 'blocked'].includes(a.status));
  for (const d of denied) C(`Residual risk: "${d.description}" was ${d.status}`, false, 'Containment gap accepted by human decision or policy');
  for (const t of incident.recovery.tasks.filter((x) => x.kind === 'restore_backup' && sim.env.hosts[x.host])) { const h = sim.env.hosts[t.host]; C(`${t.host} restored from ${t.backup}`, h.restoredFrom === t.backup && h.compromised === false, `content hash ${h.contentHash.slice(0, 12)}…`); }
  for (const g of incident.recovery.tasks.filter((x) => x.gap)) C(`Backup gap on ${g.host}`, ['done', 'skipped'].includes(g.status), 'Manual rebuild task ' + g.status);
  const open = incident.recovery.tasks.filter((t) => !['done', 'skipped'].includes(t.status));
  C('All recovery tasks complete', open.length === 0, open.length ? `${open.length} open` : 'none open');
  C('No new alerts on affected entities since containment', newAlerts === 0, `${newAlerts} new alert(s)`);
  for (const r of incident.recovery.readiness.filter((x) => x.backup)) C(`Backup ${r.backup.id} integrity preserved`, (sim.env.backups[r.host] || []).some((b) => b.id === r.backup.id && b.verified === r.backup.verified), 'backup untouched');
  return { generatedAt: new Date().toISOString(), checks, passed: checks.every((c) => c.pass), failed: checks.filter((c) => !c.pass).length };
}
module.exports = { checkTask, plan, runTask, verify, readiness };
