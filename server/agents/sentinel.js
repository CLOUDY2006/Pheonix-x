'use strict';
// SENTINEL — Threat Detection Agent. Rule-based detection + z-score anomaly model.
// Input: one normalized event. Output: zero or more schema-validated alerts. Tools: none (read-only on event stream).
// Permissions: READ events. Cannot act on any system.
const { uid, clamp } = require('../core/util');
const { validate, SPECS } = require('../core/schema');
const registry = require('../core/registry');
const suppress = require('../core/suppressions');
const cfg = require('../core/config');
const { businessHours } = require('../sim/baselines');
const sim = require('../sim/enterprise');
const TH = { bruteCount: +globalThis.process.env.PHOENIX_TH_BRUTE || 5, massFiles: +globalThis.process.env.PHOENIX_TH_MASS_FILES || 100, massMB: +globalThis.process.env.PHOENIX_TH_MASS_MB || 400, exfilMB: +globalThis.process.env.PHOENIX_TH_EXFIL_MB || 200, renameCount: +globalThis.process.env.PHOENIX_TH_RENAMES || 50, sprayUsers: +globalThis.process.env.PHOENIX_TH_SPRAY_USERS || 4 };
const HRS = (globalThis.process.env.PHOENIX_BUSINESS_HOURS || '').match(/^(\d+)-(\d+)$/); const BH = HRS ? [+HRS[1], +HRS[2]] : businessHours; const OFFSET = +globalThis.process.env.PHOENIX_UTC_OFFSET_HOURS || 0;

const WTH = { probe: +globalThis.process.env.PHOENIX_TH_WEB_PROBE || 5, flood4xx: +globalThis.process.env.PHOENIX_TH_WEB_4XX || 60, inject: +globalThis.process.env.PHOENIX_TH_WEB_INJECT || 3, waf: +globalThis.process.env.PHOENIX_TH_WEB_WAF || 10 };
// Paths that only scanners ask for, and payload fragments typical of injection / traversal attempts.
const PROBE = /(^|\/)(\.env|\.git(\/|$)|\.aws|\.ssh|\.htaccess|\.htpasswd|wp-admin|wp-login|xmlrpc\.php|phpmyadmin|pma|adminer|server-status|actuator|cgi-bin|vendor\/phpunit|etc\/passwd|id_rsa|config\.(json|yml|yaml|php)|backup\.(zip|sql|tar)|\.DS_Store)/i;
const INJECT = /(union(\s|%20|\+)+select|(\'|%27)(\s|%20|\+)*or(\s|%20|\+)*(\'|%27)?1(\'|%27)?=|<script|%3cscript|\.\.(\/|%2f){2,}|%2e%2e(\/|%2f)|\$\{jndi:|\bsleep\(\d|information_schema|\/bin\/(ba)?sh|;\s*cat\s+\/etc)/i;
let S;
function reset() { S = { fails: {}, failIp: {}, logins: {}, cool: {}, dl: {}, stats: {}, beacons: {}, renames: {}, api4xx: {}, token: {}, webProbe: {}, web4xx: {}, webInj: {}, waf: {} }; }
reset();

const win = (map, key, ts, ms, item) => { const a = (map[key] ||= []); a.push({ ts, ...item }); while (a.length && ts - a[0].ts > ms) a.shift(); return a; };
const sevOf = (r) => (r >= 85 ? 'critical' : r >= 65 ? 'high' : r >= 40 ? 'medium' : 'low');
const isInternal = (ip) => !ip || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
const hourOf = (e) => (e.orgHour ?? (new Date(e.ts).getUTCHours() + OFFSET + 24) % 24);
const offHours = (e) => { const h = hourOf(e); return h < BH[0] || h >= BH[1]; };

// Welford online mean/variance with weak prior so the model works from the first event.
function zscore(key, x) {
  const s = (S.stats[key] ||= { n: 20, mean: 2e6, m2: 20 * (1.5e6 ** 2) });
  const sd = Math.sqrt(s.m2 / s.n) || 1;
  const z = (x - s.mean) / sd;
  if (z < 3) { s.n++; const d = x - s.mean; s.mean += d / s.n; s.m2 += d * (x - s.mean); } // only learn from non-anomalous points
  return z;
}

const decodeSafe = (p) => { try { return decodeURIComponent(p); } catch { return p; } };
function process(e) {
  const out = [];
  const t = new Date(e.ts).getTime();
  const user = e.user ? registry.userFor(e) : null;
  const emit = (rule, category, base, evidenceIds, evidenceText, affected, action, mitre, extra = {}) => {
    if (suppress.match(rule, affected)) return;
    const ck = rule + '|' + [affected.users[0], affected.hosts[0], affected.ips[0], affected.domains[0], /^R-(PLATFORM|WEB)/.test(rule) ? affected.resources[0] : ''].join(',');
    if (S.cool[ck] && t - S.cool[ck] < 120e3) return; S.cool[ck] = t;
    const riskScore = clamp(Math.round(base), 0, 100);
    const alert = { id: uid('alr'), agent: 'SENTINEL', category, rule, riskScore, severity: sevOf(riskScore), evidence: evidenceIds, evidenceSummary: evidenceText, affected, recommendedAction: action, ts: e.ts, mitre, model: extra.model || 'rule', origin: e.origin, scenarioId: e.scenarioId };
    const v = validate(SPECS.alert, alert, 'alert');
    if (!v.ok) throw new Error('SENTINEL produced invalid alert: ' + v.errors.join('; '));
    out.push(alert);
  };
  const A = (o) => ({ users: o.users || [], hosts: o.hosts || [], ips: o.ips || [], resources: o.resources || [], domains: o.domains || [], hashes: o.hashes || [] });

  // ---- Authentication ----
  if (e.type === 'login_failed') {
    const f = win(S.fails, e.user || e.ip, t, 300e3, { id: e.id });
    if (f.length >= TH.bruteCount) emit('R-BRUTE', 'Brute Force', 55 + Math.min(20, f.length * 2), f.map((x) => x.id), `${f.length} failed logins for ${e.user} in 5 min from ${e.ip}`, A({ users: [e.user], ips: [e.ip] }), 'Investigate; consider blocking source IP', [{ id: 'T1110', name: 'Brute Force', status: 'indicated' }]);
    const fi = win(S.failIp, e.ip, t, 300e3, { id: e.id, user: e.user });
    const distinct = new Set(fi.map((x) => x.user));
    if (distinct.size >= TH.sprayUsers) emit('R-SPRAY', 'Password Spraying', 65, fi.map((x) => x.id), `${e.ip} failed against ${distinct.size} distinct accounts in 5 min`, A({ users: [...distinct], ips: [e.ip] }), 'Block source IP; review targeted accounts', [{ id: 'T1110.003', name: 'Password Spraying', status: 'indicated' }]);
  }
  if (e.type === 'login_success' && user) {
    const f = (S.fails[e.user] || []).filter((x) => t - x.ts <= 600e3);
    const unusualGeo = e.geo && user.homeGeo && e.geo !== user.homeGeo; // no baseline yet (learning) => no geo verdict
    const knownDev = e.details?.knownDevice === true || user.devices.includes(e.device);
    const mfa = e.details?.mfa === true;
    const prev = S.logins[e.user]; S.logins[e.user] = { geo: e.geo, ts: t, id: e.id };
    let score = 0; const notes = []; const ev = [e.id];
    if (f.length >= TH.bruteCount) { score = Math.max(score, 78); notes.push(`successful login after ${f.length} failures`); ev.unshift(...f.map((x) => x.id)); }
    if (unusualGeo) { score += knownDev && mfa ? 32 : 22; notes.push(`login from ${e.geo} (home ${user.homeGeo})${knownDev ? ', known device' : ', UNKNOWN device'}${mfa ? ', MFA passed' : ', no MFA'}`); }
    if (prev && prev.geo !== e.geo && t - prev.ts < 3600e3 && e.geo) { score += 22; notes.push(`impossible travel ${prev.geo} → ${e.geo} within ${Math.round((t - prev.ts) / 60e3)} min`); ev.push(prev.id); }
    if (offHours(e)) { score += 12; notes.push(`off-hours (${hourOf(e)}:00)`); }
    if (user.role === 'cfo' || user.role === 'sysadmin') score += 5;
    if (score < 30 && f.length === 0) registry.learn(user, e);
    if (score >= 30) emit(f.length >= TH.bruteCount ? 'R-CRED-COMPROMISE' : 'R-ANOMALOUS-LOGIN', f.length >= TH.bruteCount ? 'Credential Compromise' : 'Anomalous Login', score, ev, notes.join('; '), A({ users: [e.user], ips: [e.ip], hosts: e.host ? [e.host] : [] }), score < 45 ? 'Monitor; verify with user if risk rises' : 'Investigate account; revoke sessions if unverified', f.length >= TH.bruteCount ? [{ id: 'T1078', name: 'Valid Accounts', status: 'indicated' }, { id: 'T1110', name: 'Brute Force', status: 'indicated' }] : [{ id: 'T1078', name: 'Valid Accounts', status: 'hypothesis' }]);
  }
  if (e.type === 'privilege_change') {
    const approved = e.details?.actor === 'dave.okafor' && e.details?.ticket;
    if (!approved) emit('R-PRIV', 'Privilege Escalation', 72 + (e.details?.newRole === 'admin' ? 10 : 0), [e.id], `${e.details?.actor || 'unknown'} changed ${e.user} role to ${e.details?.newRole} without change ticket`, A({ users: [e.user, e.details?.actor].filter(Boolean), hosts: e.host ? [e.host] : [] }), 'Verify change; revert if unauthorized', [{ id: 'T1098', name: 'Account Manipulation', status: 'indicated' }]);
  }

  // ---- File / exfil ----
  if (e.type === 'file_download' || e.type === 'file_read') {
    const bytes = e.bytes || 0;
    const w = win(S.dl, e.user, t, 600e3, { id: e.id, n: e.count || 1, bytes });
    const files = w.reduce((a, x) => a + x.n, 0), tot = w.reduce((a, x) => a + x.bytes, 0);
    const sens = e.resource && sim.env.resources[e.resource]?.sensitivity === 'restricted';
    if (files >= TH.massFiles || tot > TH.massMB * 1e6) {
      let s = 70 + (sens ? 8 : 0) + (offHours(e) ? 10 : 0);
      emit('R-MASS-DOWNLOAD', 'Data Collection / Exfiltration Risk', s, w.map((x) => x.id), `${files} files / ${(tot / 1e6).toFixed(0)} MB accessed by ${e.user} in 10 min${offHours(e) ? ' (off-hours)' : ''}${sens ? ' on restricted data' : ''}`, A({ users: [e.user], hosts: e.host ? [e.host] : [], resources: e.resource ? [e.resource] : [] }), 'Investigate; restrict resource and suspend user pending approval', [{ id: 'T1005', name: 'Data from Local System', status: 'indicated' }, { id: 'T1530', name: 'Data from Cloud Storage', status: 'hypothesis' }]);
    } else if (bytes > 50e6) {
      const z = zscore('dl:' + e.user, bytes);
      if (z > 4) emit('M-ZSCORE-DL', 'Anomalous File Volume', 52, [e.id], `Single transfer ${(bytes / 1e6).toFixed(0)} MB is ${z.toFixed(1)}σ above ${e.user}'s baseline`, A({ users: [e.user], resources: e.resource ? [e.resource] : [] }), 'Review; correlate with other signals', [], { model: 'zscore' });
    } else zscore('dl:' + e.user, bytes);
    if (e.type === 'file_read' && e.user) { /* normal; used only for baseline above */ }
  }
  if (e.type === 'file_rename') {
    const enc = /\.(locked|enc|crypt|phxlock)$/i.test(e.details?.newExt || e.resource || '');
    if (enc) {
      const w = win(S.renames, e.host, t, 60e3, { id: e.id, n: e.count || 1 });
      const n = w.reduce((a, x) => a + x.n, 0);
      if (n >= TH.renameCount) emit('R-RANSOMWARE', 'Ransomware', 96, w.map((x) => x.id), `${n} files renamed with encrypted extension on ${e.host} within 60s`, A({ hosts: [e.host], users: e.user ? [e.user] : [] }), 'IMMEDIATE: isolate host, protect backups', [{ id: 'T1486', name: 'Data Encrypted for Impact', status: 'indicated' }]);
    }
  }
  if (e.type === 'shadow_copy_deleted') emit('R-SHADOW-DEL', 'Inhibit Recovery', 88, [e.id], `Volume shadow copies deleted on ${e.host} by ${e.details?.process || 'unknown process'}`, A({ hosts: [e.host], users: e.user ? [e.user] : [] }), 'Isolate host; verify backup integrity', [{ id: 'T1490', name: 'Inhibit System Recovery', status: 'indicated' }]);

  // ---- Network ----
  if (e.type === 'outbound_conn' && !isInternal(e.ip)) {
    if ((e.bytes || 0) > TH.exfilMB * 1e6) emit('R-EXFIL', 'Possible Data Exfiltration', 82, [e.id], `${(e.bytes / 1e6).toFixed(0)} MB sent from ${e.host || e.user} to ${e.ip}${e.domain ? ' (' + e.domain + ')' : ''}`, A({ users: e.user ? [e.user] : [], hosts: e.host ? [e.host] : [], ips: [e.ip], domains: e.domain ? [e.domain] : [] }), 'Block destination; investigate source host', [{ id: 'T1041', name: 'Exfiltration Over C2 Channel', status: 'hypothesis' }, { id: 'T1567', name: 'Exfiltration Over Web Service', status: 'hypothesis' }]);
  }
  if (e.type === 'beacon') {
    const w = win(S.beacons, e.host + '>' + e.ip, t, 300e3, { id: e.id });
    if (w.length >= 5) emit('R-BEACON', 'Command & Control', 78, w.map((x) => x.id), `${w.length} periodic low-volume connections ${e.host} → ${e.ip} in 5 min (fixed interval)`, A({ hosts: [e.host], ips: [e.ip], domains: e.domain ? [e.domain] : [] }), 'Block destination IP; check host for implant', [{ id: 'T1071', name: 'Application Layer Protocol', status: 'indicated' }]);
  }

  // ---- Phishing / endpoint ----
  if (e.type === 'email_link_click' && (e.details?.domainAgeDays ?? 999) < 30) emit('R-PHISH-CLICK', 'Phishing', 52, [e.id], `${e.user} clicked link to ${e.domain} (registered ${e.details.domainAgeDays} days ago)`, A({ users: [e.user], domains: [e.domain], hosts: e.host ? [e.host] : [] }), 'Check domain reputation; watch for follow-on activity', [{ id: 'T1566.002', name: 'Spearphishing Link', status: 'hypothesis' }]);
  if (e.type === 'macro_exec') emit('R-MACRO', 'Malware Execution', 74, [e.id], `Office app spawned ${e.details?.child} on ${e.host}${e.hash ? ' (sha256 ' + e.hash.slice(0, 12) + '…)' : ''}`, A({ users: e.user ? [e.user] : [], hosts: [e.host], hashes: e.hash ? [e.hash] : [] }), 'Isolate host pending analysis; check hash reputation', [{ id: 'T1204.002', name: 'Malicious File', status: 'indicated' }, { id: 'T1059.005', name: 'Visual Basic', status: 'hypothesis' }]);

  // ---- API ----
  if (e.type === 'api_call') {
    const tid = e.details?.tokenId;
    if (tid && e.geo) {
      const first = (S.token[tid] ||= { geo: e.geo, ip: e.ip });
      if (first.geo !== e.geo) emit('R-TOKEN-REUSE', 'Token Theft', 68, [e.id], `Token ${tid} first seen from ${first.geo}, now used from ${e.geo} (${e.ip})`, A({ users: e.user ? [e.user] : [], ips: [e.ip] }), 'Revoke token; investigate originating session', [{ id: 'T1528', name: 'Steal Application Access Token', status: 'hypothesis' }]);
    }
    if ((e.details?.status || 200) >= 400) { const w = win(S.api4xx, e.ip, t, 60e3, { id: e.id }); if (w.length >= 15) emit('R-API-ENUM', 'API Enumeration', 50, w.map((x) => x.id), `${w.length} API errors in 60s from ${e.ip}`, A({ ips: [e.ip], users: e.user ? [e.user] : [] }), 'Rate-limit source', [{ id: 'T1087', name: 'Account Discovery', status: 'hypothesis' }]); }
  }
  if (e.type === 'mailbox_rule_created' && e.details?.forwardExternal) emit('R-MAIL-FWD', 'Email Collection', 70, [e.id], `Mailbox rule forwarding to external ${e.details.forwardTo} created for ${e.user}`, A({ users: [e.user], ips: e.ip ? [e.ip] : [], domains: [e.details.forwardTo.split('@')[1]] }), 'Remove rule; revoke sessions', [{ id: 'T1114.003', name: 'Email Forwarding Rule', status: 'indicated' }]);

  if (e.type === 'email_reported') emit('R-PHISH-REPORT', 'Phishing (user-reported)', 48, [e.id], `${e.user} reported suspicious email "${e.details?.subject}" from ${e.details?.from}`, A({ users: [e.user], domains: (e.details?.urls || []).map((u) => { try { return new URL(u).hostname; } catch { return null; } }).filter(Boolean) }), 'Analyse message; check indicators; find other recipients and clickers', [{ id: 'T1566.002', name: 'Spearphishing Link', status: 'hypothesis' }]);

  // ---- Web traffic (deployment platforms, CDN/WAF, web servers) ----
  if (e.type === 'web_request' && e.ip && !isInternal(e.ip)) {
    const path = String(e.resource || '');
    if (PROBE.test(path)) { const w = win(S.webProbe, e.ip, t, 300e3, { id: e.id, path: path.split('?')[0] }); const distinct = new Set(w.map((x) => x.path)); if (distinct.size >= WTH.probe) emit('R-WEB-PROBE', 'Web Reconnaissance', 52 + Math.min(15, distinct.size), w.map((x) => x.id), `${e.ip} requested ${distinct.size} sensitive/scanner paths in 5 min (e.g. ${[...distinct].slice(0, 3).join(', ')}) on ${e.host || 'your site'}`, A({ ips: [e.ip], resources: e.host ? [e.host] : [] }), 'Block source IP at the edge/WAF; confirm none of the probed files are exposed', [{ id: 'T1595.002', name: 'Vulnerability Scanning', status: 'indicated' }]); }
    if (INJECT.test(decodeSafe(path))) { const w = win(S.webInj, e.ip, t, 300e3, { id: e.id }); if (w.length >= WTH.inject) emit('R-WEB-INJECT', 'Web Application Attack', 66 + Math.min(14, w.length * 2), w.map((x) => x.id), `${w.length} requests with injection/traversal payloads from ${e.ip} in 5 min (latest: ${path.slice(0, 80)})`, A({ ips: [e.ip], resources: e.host ? [e.host] : [] }), 'Block source IP; review application logs for successful exploitation', [{ id: 'T1190', name: 'Exploit Public-Facing Application', status: 'indicated' }]); }
    if ((e.details?.status || 0) >= 400 && (e.details?.status || 0) < 500) { const w = win(S.web4xx, e.ip, t, 60e3, { id: e.id }); if (w.length >= WTH.flood4xx) emit('R-WEB-FLOOD', 'Web Abuse / Scanning', 45, w.map((x) => x.id), `${w.length} client-error responses in 60 s from ${e.ip}`, A({ ips: [e.ip], resources: e.host ? [e.host] : [] }), 'Rate-limit or block source', [{ id: 'T1595', name: 'Active Scanning', status: 'hypothesis' }]); }
  }
  if (e.type === 'waf_block' && e.ip) { const w = win(S.waf, e.ip, t, 300e3, { id: e.id }); if (w.length >= WTH.waf) emit('R-WEB-WAF', 'Blocked Attack Traffic', 55 + Math.min(15, w.length), w.map((x) => x.id), `${w.length} requests blocked/challenged by ${e.details?.platform || 'the WAF'} from ${e.ip} in 5 min (rule ${e.details?.rule || 'n/a'})`, A({ ips: [e.ip], resources: e.host ? [e.host] : [] }), 'Attack is already being blocked; consider a permanent IP block and review rule coverage', [{ id: 'T1190', name: 'Exploit Public-Facing Application', status: 'hypothesis' }]); }

  // ---- Deployment-platform / source-control account & configuration changes ----
  if (e.type === 'platform_change') {
    const c = e.details?.change, who = e.details?.actor || 'unknown actor', plat = e.details?.platform || 'platform', what = e.details?.what || c;
    const R = { secret_exposed: [82, 'Credential Exposure', 'T1552.001', 'Credentials In Files', 'Rotate the exposed secret NOW, then investigate use of it'], repo_public: [78, 'Data Exposure', 'T1530', 'Data from Cloud Storage', 'Confirm the repository was meant to be public; make private if not'], deploy_key_added: [60, 'Persistence', 'T1098.001', 'Additional Cloud Credentials', 'Verify the deploy key is expected; remove if not'], branch_protection_removed: [62, 'Defense Evasion', 'T1562', 'Impair Defenses', 'Restore branch protection; review recent pushes'], force_push: [58, 'Tampering', 'T1565', 'Data Manipulation', 'Review the rewritten history and restore if needed'], member_added: [48, 'Persistence', 'T1136', 'Create Account', 'Confirm the new member is expected'], env_var_changed: [50, 'Configuration Change', 'T1098', 'Account Manipulation', 'Confirm the environment-variable change was intended (secrets live here)'], domain_changed: [58, 'Configuration Change', 'T1584.001', 'Compromise Infrastructure: Domains', 'Confirm the domain change (risk: takeover / traffic redirection)'], project_deleted: [70, 'Impact', 'T1485', 'Data Destruction', 'Confirm deletion was intended; restore from backup if not'], integration_changed: [55, 'Persistence', 'T1098', 'Account Manipulation', 'Review the removed/changed integration'], waf_attack_signal: [60, 'Attack Signal', 'T1190', 'Exploit Public-Facing Application', 'Review the platform firewall dashboard'], service_state_changed: [42, 'Configuration Change', 'T1489', 'Service Stop', 'Confirm the service was suspended/changed intentionally'], vuln_critical: [40, 'Vulnerability', 'T1190', 'Exploit Public-Facing Application', 'Patch the vulnerable dependency'] }[c];
    if (R) emit('R-PLATFORM-' + String(c).toUpperCase().replace(/_/g, '-'), R[1], R[0], [e.id], `${plat}: ${what} by ${who}${e.resource ? ' on ' + e.resource : ''}`, A({ ips: e.ip ? [e.ip] : [], resources: e.resource ? [e.resource] : [] }), R[4], [{ id: R[2], name: R[3], status: 'indicated' }]);
  }

  // ---- Cloud audit ----
  if (e.type === 'iam_attach_policy' && /Administrator/i.test(e.details?.policyArn || '')) emit('R-CLOUD-ADMIN', 'Cloud Privilege Escalation', 84, [e.id], `${e.user} attached ${e.details.policyArn} to ${e.resource}`, A({ users: [e.user], ips: e.ip ? [e.ip] : [], resources: [e.resource] }), 'Detach policy (approval); review actor', [{ id: 'T1098.003', name: 'Additional Cloud Roles', status: 'indicated' }]);
  if (e.type === 'create_access_key') emit('R-CLOUD-KEY', 'Persistence', 62, [e.id], `${e.user} created access key for ${e.resource}`, A({ users: [e.user], ips: e.ip ? [e.ip] : [], resources: [e.resource] }), 'Verify key creation', [{ id: 'T1098.001', name: 'Additional Cloud Credentials', status: 'hypothesis' }]);
  if (e.type === 'put_bucket_acl' && e.details?.acl === 'public') emit('R-CLOUD-PUBLIC', 'Data Exposure', 78, [e.id], `Bucket ${e.resource} made public by ${e.user}`, A({ users: [e.user], ips: e.ip ? [e.ip] : [], resources: [e.resource] }), 'Make bucket private (approval)', [{ id: 'T1530', name: 'Data from Cloud Storage', status: 'hypothesis' }]);
  if (e.type === 'stop_logging') emit('R-CLOUD-BLIND', 'Defense Evasion', 92, [e.id], `${e.user} attempted to stop audit logging (${e.details?.eventName || 'StopLogging'})`, A({ users: [e.user], ips: e.ip ? [e.ip] : [], resources: [e.resource].filter(Boolean) }), 'Re-enabling logging is a security-control change: human authorization required', [{ id: 'T1562.008', name: 'Disable Cloud Logs', status: 'indicated' }]);

  return out;
}
module.exports = { process, reset, TH, WTH };
