'use strict';
// GUARDIAN — Automated Containment Agent with a permission-based execution system.
//   AUTOMATIC          low-risk, reversible, and ONLY against assets flagged env=sandbox
//   APPROVAL_REQUIRED  account suspension, host isolation, cloud/prod config changes — a human must approve
//   RESTRICTED         destructive / shutdown / security-control changes — the agent can NEVER execute these,
//                      not even if "approved" in the UI. They are listed as manual-only recommendations.
// Guardian has NO shell, NO eval, NO arbitrary scripts: only the whitelisted functions in CATALOG, which mutate
// the simulated enterprise (and, optionally, a real Supabase Auth project that you explicitly configure).
const { uid } = require('../core/util');
const audit = require('../core/audit');
const sim = require('../sim/enterprise');
const { validate, SPECS } = require('../core/schema');
const cfg = require('../core/config');
const connectors = require('../connectors');
const autonomy = require('../core/autonomy');

const config = { autoContain: cfg.autoContain, environment: cfg.isProd ? 'production' : 'sandbox' };

const supaMap = () => { try { return JSON.parse(process.env.PHOENIX_SUPABASE_USER_MAP || '{}'); } catch { return {}; } };
const supaOn = () => !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);
async function supaBan(userId, ban) {
  const r = await fetch(`${process.env.SUPABASE_URL}/auth/v1/admin/users/${userId}`, { method: 'PUT', headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: 'Bearer ' + process.env.SUPABASE_SERVICE_ROLE_KEY, 'content-type': 'application/json' }, body: JSON.stringify({ ban_duration: ban ? '876000h' : 'none' }), signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error('Supabase HTTP ' + r.status);
  const j = await r.json();
  return { providerConfirmed: ban ? !!j.banned_until : !j.banned_until, banned_until: j.banned_until || null };
}

const env = () => sim.env;
const CATALOG = {
  block_ip: { tier: 'automatic', reversible: true, describe: (t) => `Block ${t.ip} at simulated firewall`,
    run: (t) => { env().firewall.blockedIPs.add(t.ip); return { detail: `${t.ip} added to blocklist` }; }, undo: (t) => { env().firewall.blockedIPs.delete(t.ip); return { detail: `${t.ip} unblocked` }; } },
  revoke_sessions: { tier: 'automatic', reversible: false, describe: (t) => `Revoke all active sessions for ${t.user}`,
    run: (t) => { const u = env().users[t.user]; if (!u) throw new Error('unknown user'); const n = u.sessions.length; u.sessions = []; u.tokens = []; u.sessionsRevokedAt = new Date().toISOString(); return { detail: `${n} session(s) and all tokens revoked` }; } },
  revoke_token: { tier: 'automatic', reversible: false, describe: (t) => `Revoke access token ${t.tokenId} (${t.user})`,
    run: (t) => { const u = env().users[t.user]; if (!u) throw new Error('unknown user'); u.tokens = u.tokens.filter((x) => x !== t.tokenId); u.revokedTokens = [...(u.revokedTokens || []), t.tokenId]; return { detail: `token ${t.tokenId} revoked` }; } },
  restrict_resource: { tier: 'automatic', reversible: true, describe: (t) => `Restrict access to ${t.resource} (read-only for owner, deny others)`,
    run: (t) => { const r = env().resources[t.resource] ||= { env: 'sandbox', sensitivity: 'unknown' }; r.restricted = true; return { detail: `${t.resource} access restricted` }; }, undo: (t) => { env().resources[t.resource].restricted = false; return { detail: 'restriction lifted' }; } },
  disable_account: { tier: 'approval', reversible: true, describe: (t) => `Disable (suspend) account ${t.user}`,
    run: async (t) => { const u = env().users[t.user]; if (!u) throw new Error('unknown user'); u.status = 'suspended'; u.sessions = []; u.tokens = [];
      const sid = supaMap()[t.user]; if (supaOn() && sid) { const s = await supaBan(sid, true); return { detail: `${t.user} suspended in simulated directory AND Supabase Auth`, provider: 'supabase', providerConfirmed: s.providerConfirmed }; }
      return { detail: `${t.user} suspended in simulated directory` }; },
    undo: async (t) => { env().users[t.user].status = 'active'; const sid = supaMap()[t.user]; if (supaOn() && sid) await supaBan(sid, false); return { detail: `${t.user} re-enabled` }; } },
  force_password_reset: { tier: 'approval', reversible: false, describe: (t) => `Force a password reset for ${t.user} at next sign-in`,
    run: (t) => { const u = env().users[t.user]; if (!u) throw new Error('unknown user'); u.sessions = []; u.tokens = []; u.passwordResetRequired = true; u.credentialsRotated = true; u.mfa = true; return { detail: `${t.user}: password expired, sessions cleared (simulated directory)` }; } },
  isolate_host: { tier: 'approval', reversible: true, describe: (t) => `Network-isolate host ${t.host} (EDR quarantine)`,
    run: (t) => { const h = env().hosts[t.host]; if (!h) throw new Error('unknown host'); h.isolated = true; h.status = 'isolated'; return { detail: `${t.host} isolated from network` }; }, undo: (t) => { const h = env().hosts[t.host]; h.isolated = false; h.status = 'online'; return { detail: `${t.host} reconnected` }; } },
  detach_cloud_policy: { tier: 'approval', reversible: true, describe: (t) => `Detach ${t.policy} from cloud role ${t.role}`,
    run: (t) => { const r = env().cloud.roles[t.role]; if (!r) throw new Error('unknown role'); r.policies = r.policies.filter((p) => !p.includes(t.policy)); return { detail: `${t.policy} detached from ${t.role}` }; } },
  make_bucket_private: { tier: 'approval', reversible: true, describe: (t) => `Set bucket ${t.bucket} to private`,
    run: (t) => { const b = env().cloud.buckets[t.bucket]; if (!b) throw new Error('unknown bucket'); b.public = false; return { detail: `${t.bucket} public access blocked` }; } },
  // ---- RESTRICTED: registered only so they are recognised and refused ----
  delete_data: { tier: 'restricted' }, shutdown_host: { tier: 'restricted' }, wipe_host: { tier: 'restricted' }, modify_security_control: { tier: 'restricted' },
};

// Policy engine: the single place that decides who may run what. The autonomy mode (watch / balanced / full),
// protected entities and the hourly budget decide whether the AI may act alone; restricted actions never run.
function classify(type, target = {}, opts = {}) {
  const c = CATALOG[type];
  if (!c) return { tier: 'restricted', why: 'Unknown action types are denied by default' };
  if (c.tier === 'restricted') return { tier: 'restricted', why: 'Destructive / security-control action: never executed by the AI in any mode' };
  const asset = target.host ? env().hosts[target.host] : target.resource ? env().resources[target.resource] : target.user ? env().users[target.user] : null;
  return autonomy.decide(type, c.tier, target, { assetEnv: asset?.env || null, forceWatch: !config.autoContain, ...opts });
}

function mk(type, target, reason, extra = {}) {
  const p = classify(type, target);
  return { id: uid('act'), type, target, tier: p.tier, autonomy: autonomy.getMode(), policyReason: p.why, description: CATALOG[type]?.describe?.(target) || type, reason, status: 'planned', simulated: true, ...extra };
}

function plan(incident, inv, intel) {
  const actions = [], manualOnly = [];
  const A = incident.alerts, has = (r) => A.some((a) => a.rule === r);
  const top = Math.max(...A.map((a) => a.riskScore));
  if (incident.disposition === 'monitor') return { incidentId: incident.id, actions: [], manualOnly: [], note: 'Low risk: monitor only, no containment proposed.' };
  const verdict = (v) => intel.indicators.find((i) => i.indicator === v)?.verdict;
  const seen = new Set(); const add = (a) => { const k = a.type + JSON.stringify(a.target); if (!seen.has(k)) { seen.add(k); actions.push(a); } };

  // IPs: block external IPs implicated by alerts that point at an attacker/destination
  const ipRules = ['R-BRUTE', 'R-SPRAY', 'R-CRED-COMPROMISE', 'R-EXFIL', 'R-BEACON', 'R-TOKEN-REUSE', 'R-MAIL-FWD', 'R-CLOUD-ADMIN', 'R-ANOMALOUS-LOGIN'];
  for (const a of A.filter((x) => ipRules.includes(x.rule))) for (const ip of a.affected.ips) {
    if (/^(10\.|192\.168\.)/.test(ip)) continue;
    const v = verdict(ip);
    const isHome = Object.values(require('../sim/baselines').geos).some((g) => ip.startsWith(g.ip));
    if (isHome || (a.rule === 'R-ANOMALOUS-LOGIN' && v !== 'malicious')) continue; // never block an employee's normal IP on a hunch
    add(mk('block_ip', { ip }, `${a.rule}; intel verdict: ${v || 'not checked'}${v === 'unknown' ? ' (unknown ≠ malicious; blocked because alert behaviour implicates it)' : ''}`, { evidenceRefs: a.evidence }));
  }
  // Users
  const compRules = ['R-CRED-COMPROMISE', 'R-TOKEN-REUSE', 'R-MAIL-FWD', 'R-MASS-DOWNLOAD', 'R-PRIV', 'R-CLOUD-ADMIN', 'R-PHISH-CLICK', 'R-CLOUD-KEY'];
  for (const a of A.filter((x) => compRules.includes(x.rule))) for (const u of a.affected.users) {
    if (!env().users[u] && !/^ci-|^svc-/.test(u)) { /* external/cloud principal without directory entry: handled by cloud actions */ }
    if (!env().users[u]) continue;
    add(mk('revoke_sessions', { user: u }, `${a.rule}: sessions may be attacker-controlled`, { evidenceRefs: a.evidence }));
    if (a.rule === 'R-TOKEN-REUSE') add(mk('revoke_token', { user: u, tokenId: 'tok-' + u }, 'Token replayed from a different geography', { evidenceRefs: a.evidence }));
    if (a.riskScore >= 70 || a.rule === 'R-CRED-COMPROMISE') add(mk('force_password_reset', { user: u }, `${a.rule}: the old password may be known to the attacker`, { evidenceRefs: a.evidence }));
    if (a.riskScore >= 70 || a.rule === 'R-CRED-COMPROMISE') add(mk('disable_account', { user: u }, `${a.rule} risk ${a.riskScore}: suspend pending credential reset`, { evidenceRefs: a.evidence }));
  }
  for (const a of A.filter((x) => x.rule === 'R-MASS-DOWNLOAD')) for (const r of a.affected.resources) add(mk('restrict_resource', { resource: r }, 'Stop further bulk access while investigating', { evidenceRefs: a.evidence }));
  // Hosts
  for (const a of A.filter((x) => ['R-RANSOMWARE', 'R-SHADOW-DEL', 'R-MACRO', 'R-BEACON'].includes(x.rule))) for (const h of a.affected.hosts) add(mk('isolate_host', { host: h }, `${a.rule}: stop spread / C2 contact`, { evidenceRefs: a.evidence }));
  // Cloud
  for (const a of A.filter((x) => x.rule === 'R-CLOUD-ADMIN')) add(mk('detach_cloud_policy', { role: a.affected.resources[0], policy: 'AdministratorAccess' }, 'Unauthorised admin grant', { evidenceRefs: a.evidence }));
  for (const a of A.filter((x) => x.rule === 'R-CLOUD-PUBLIC')) add(mk('make_bucket_private', { bucket: a.affected.resources[0] }, 'Bucket exposed publicly', { evidenceRefs: a.evidence }));
  // Restricted / manual-only recommendations (the agent will NEVER do these)
  if (has('R-CLOUD-BLIND')) manualOnly.push({ type: 'modify_security_control', description: 'Re-enable / harden CloudTrail logging and lock the trail with an SCP', tier: 'restricted', why: 'Changes a real security control — requires authorised human with change ticket' });
  if (has('R-RANSOMWARE')) {
    for (const a of A.filter((x) => x.rule === 'R-RANSOMWARE')) for (const h of a.affected.hosts) manualOnly.push({ type: 'wipe_host', description: `Re-image ${h} after forensic capture`, tier: 'restricted', why: 'Destroys evidence and data — human decision after forensics' });
    manualOnly.push({ type: 'shutdown_host', description: 'Power-off of file server', tier: 'restricted', why: 'Shutting down critical infrastructure is never automated' });
  }
  for (const m of manualOnly) audit.log('GUARDIAN', 'POLICY_RESTRICTED', { type: m.type, description: m.description, why: m.why }, incident.id);
  const out = { incidentId: incident.id, actions, manualOnly, note: `${actions.filter((a) => a.tier === 'automatic').length} automatic, ${actions.filter((a) => a.tier === 'approval').length} need approval, ${manualOnly.length} restricted (manual only)` };
  const v = validate(SPECS.plan, out, 'plan'); if (!v.ok) throw new Error('GUARDIAN invalid plan: ' + v.errors.join('; '));
  return out;
}

// The only door to execution. Re-checks policy at execution time so a tampered/stale plan can't bypass it.
async function execute(action, { incidentId = null, approvedBy = null } = {}) {
  const c = CATALOG[action.type];
  const p = classify(action.type, action.target, { ignoreBudget: action.tier === 'automatic' });
  if (p.tier === 'restricted' || !c?.run) { action.status = 'blocked'; audit.log('GUARDIAN', 'ACTION_BLOCKED_RESTRICTED', { type: action.type, target: action.target, why: p.why }, incidentId); return { ok: false, blocked: true, error: 'RESTRICTED: ' + p.why }; }
  if (p.tier === 'approval' && !approvedBy) { action.status = 'blocked'; audit.log('GUARDIAN', 'ACTION_BLOCKED_NO_APPROVAL', { type: action.type, target: action.target }, incidentId); return { ok: false, blocked: true, error: 'Approval required' }; }
  audit.log('GUARDIAN', 'ACTION_EXECUTING', { id: action.id, type: action.type, target: action.target, tier: p.tier, approvedBy }, incidentId);
  const conn = connectors.nameFor(action.type), ad = connectors.adapterFor(action.type), dry = cfg.connectorDryRun && conn !== 'sim';
  try {
    if (conn !== 'sim') {
      // ---- real-world path: only through a configured connector, only when not in dry-run, only when the provider confirms ----
      if (!ad || !ad.supports(action.type)) { action.status = 'manual_required'; action.result = { provider: conn, providerConfirmed: false, detail: `No connector for ${connectors.domainOf(action.type)}: a human must apply this and confirm it in the recovery tasks` }; audit.log('GUARDIAN', 'ACTION_MANUAL_REQUIRED', { id: action.id, type: action.type, target: action.target }, incidentId); return { ok: false, pending: true, status: action.status, error: action.result.detail }; }
      if (dry) { action.status = 'dry_run'; action.result = { provider: conn, providerConfirmed: false, dryRun: true, detail: `DRY-RUN: would ${action.description} via ${conn}. Nothing was changed.` }; audit.log('GUARDIAN', 'ACTION_DRY_RUN', { id: action.id, type: action.type, target: action.target, connector: conn }, incidentId); return { ok: false, pending: true, status: action.status, error: action.result.detail }; }
      const res = await ad.run(action.type, action.target, { incidentId, by: approvedBy, actionId: action.id });
      action.result = { providerConfirmed: false, ...res }; action.approvedBy = approvedBy; action.simulated = false;
      if (!res.providerConfirmed) { action.status = 'failed'; action.error = 'Provider did not confirm the change'; audit.log('GUARDIAN', 'ACTION_UNCONFIRMED', { id: action.id, type: action.type, result: res }, incidentId); return { ok: false, error: action.error }; }
      markAi(action, p, approvedBy); action.status = 'executed'; action.executedAt = new Date().toISOString(); audit.log('GUARDIAN', 'ACTION_EXECUTED', { id: action.id, type: action.type, result: action.result, by: approvedBy }, incidentId); return { ok: true, result: action.result };
    }
    const res = await c.run(action.target);
    markAi(action, p, approvedBy); action.status = 'executed'; action.executedAt = new Date().toISOString(); action.approvedBy = approvedBy; action.result = { provider: 'simulated-enterprise', providerConfirmed: true, ...res };
    audit.log('GUARDIAN', 'ACTION_EXECUTED', { id: action.id, type: action.type, result: action.result }, incidentId);
    return { ok: true, result: action.result };
  } catch (e) { action.status = 'failed'; action.error = e.message; audit.log('GUARDIAN', 'ACTION_FAILED', { id: action.id, error: e.message }, incidentId); return { ok: false, error: e.message }; }
}
// An action the AI took by itself is flagged so the UI can offer Unblock, and gets a lifetime (self-recovery).
function markAi(action, p, approvedBy) {
  if (p.tier !== 'automatic' || (approvedBy && !/^(ai|policy)/.test(approvedBy))) return;
  action.aiAuto = true; action.autonomyMode = autonomy.getMode(); action.rationale = p.why;
  const h = autonomy.ttlFor(action.type); if (h && CATALOG[action.type].undo) action.expiresAt = new Date(Date.now() + h * 3600e3).toISOString();
  autonomy.spend(); audit.log('GUARDIAN', 'AI_AUTO_ACTION', { id: action.id, type: action.type, target: action.target, mode: autonomy.getMode(), expiresAt: action.expiresAt || null });
}
async function rollback(action, incidentId, by) {
  const c = CATALOG[action.type]; if (action.status !== 'executed') return { ok: false };
  const live = action.result && action.result.provider !== 'simulated-enterprise';
  if (live) { if (action.result.manual) { action.status = 'rolled_back'; audit.log(by || 'RECOVERY', 'ACTION_ROLLED_BACK', { id: action.id, type: action.type, note: 'manual action: human reverses it' }, incidentId); return { ok: true }; } const ad = connectors.adapterFor(action.type); if (!ad?.undo || cfg.connectorDryRun) return { ok: false, error: 'rollback must be done manually' }; const r = await ad.undo(action.type, action.target, { incidentId, by, actionId: action.id }); if (!r.providerConfirmed) return { ok: false, error: 'provider did not confirm rollback' }; action.status = 'rolled_back'; audit.log(by || 'RECOVERY', 'ACTION_ROLLED_BACK', { id: action.id, type: action.type, result: r }, incidentId); return { ok: true, result: r }; }
  if (!c?.undo) return { ok: false };
  const res = await c.undo(action.target); action.status = 'rolled_back'; audit.log(by || 'RECOVERY', 'ACTION_ROLLED_BACK', { id: action.id, type: action.type, result: res }, incidentId); return { ok: true, result: res };
}
module.exports = { mk, plan, execute, rollback, classify, config, CATALOG, supaOn };
