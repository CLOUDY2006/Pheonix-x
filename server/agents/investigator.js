'use strict';
// INVESTIGATOR — correlates events, reconstructs the timeline + attack graph, and separates
// evidence-backed findings from hypotheses. Deterministic structured output; an LLM (optional) may only add
// a clearly labelled prose narrative on top of the structured facts and can never change them.
// Tools: read-only event store query. Permissions: READ only.
const events = require('../core/events');
const { validate, SPECS } = require('../core/schema');

const NOTABLE = new Set(['login_failed', 'login_success', 'privilege_change', 'file_download', 'file_rename', 'shadow_copy_deleted', 'outbound_conn', 'beacon', 'email_link_click', 'macro_exec', 'mailbox_rule_created', 'iam_attach_policy', 'create_access_key', 'put_bucket_acl', 'stop_logging', 'lateral_access', 'api_call', 'process_start', 'email_reported']);
const PHASE = { login_failed: 'Credential Access', login_success: 'Initial Access', email_link_click: 'Initial Access', email_reported: 'Initial Access', macro_exec: 'Execution', privilege_change: 'Privilege Escalation', create_access_key: 'Persistence', mailbox_rule_created: 'Collection', lateral_access: 'Lateral Movement', file_download: 'Collection', file_read: 'Collection', beacon: 'Command & Control', outbound_conn: 'Exfiltration', shadow_copy_deleted: 'Impact', file_rename: 'Impact', iam_attach_policy: 'Privilege Escalation', put_bucket_acl: 'Exfiltration', stop_logging: 'Defense Evasion', api_call: 'Collection' };

function describe(e) {
  const who = e.user || e.host || e.ip || '?';
  const m = {
    login_failed: () => `Failed login for ${e.user} from ${e.ip} (${e.geo || '?'})`,
    login_success: () => `Successful login for ${e.user} from ${e.ip} (${e.geo || '?'})${e.details?.mfa === false ? ' without MFA' : ''}`,
    privilege_change: () => `${e.details?.actor || '?'} set ${e.user} role → ${e.details?.newRole}${e.details?.ticket ? '' : ' (no change ticket)'}`,
    file_download: () => `${who} downloaded ${e.count || 1} file(s), ${((e.bytes || 0) / 1e6).toFixed(0)} MB from ${e.resource}`,
    file_read: () => `${who} read ${e.resource}`,
    file_rename: () => `${e.count || 1} files renamed to ${e.details?.newExt || '?'} on ${e.host}`,
    shadow_copy_deleted: () => `Shadow copies deleted on ${e.host} by ${e.details?.process}`,
    outbound_conn: () => `${e.host || e.user} → ${e.ip}${e.domain ? ' (' + e.domain + ')' : ''}, ${((e.bytes || 0) / 1e6).toFixed(1)} MB out`,
    beacon: () => `Beacon ${e.host} → ${e.ip}${e.domain ? ' (' + e.domain + ')' : ''}`,
    email_link_click: () => `${e.user} clicked link to ${e.domain}`,
    macro_exec: () => `${e.details?.parent} on ${e.host} spawned ${e.details?.child}`,
    mailbox_rule_created: () => `Mailbox rule created for ${e.user}${e.details?.forwardTo ? ' forwarding to ' + e.details.forwardTo : ''}`,
    iam_attach_policy: () => `${e.user} attached ${e.details?.policyArn} to ${e.resource}`,
    create_access_key: () => `${e.user} created access key for ${e.resource}`,
    put_bucket_acl: () => `${e.user} set bucket ${e.resource} ACL → ${e.details?.acl}`,
    stop_logging: () => `${e.user} attempted ${e.details?.eventName || 'StopLogging'} on audit trail`,
    lateral_access: () => `${e.user} accessed ${e.host} from ${e.details?.fromHost || e.ip} via ${e.details?.protocol || '?'}`,
    api_call: () => `API ${e.resource} by ${e.user || '?'} from ${e.ip} (${e.geo || '?'}), HTTP ${e.details?.status}`,
    email_reported: () => `${e.user} reported email "${e.details?.subject}" from ${e.details?.from}`,
    process_start: () => `${e.resource} started on ${e.host}`,
  }[e.type];
  return m ? m() : `${e.type} ${who}`;
}

function gather(incident) {
  const ids = new Set(incident.alerts.flatMap((a) => a.evidence));
  const ent = incident.entities;
  const first = events.byIds([...ids]).map((e) => +new Date(e.ts)).sort((a, b) => a - b)[0] || Date.now();
  const rel = events.all().filter((e) => {
    if (ids.has(e.id)) return true;
    if (+new Date(e.ts) < first - 3600e3) return false;
    if (e.origin === 'generated') return false; // background noise is not attack evidence
    const hit = (e.user && ent.users.includes(e.user)) || (e.host && ent.hosts.includes(e.host)) || (e.ip && ent.ips.includes(e.ip));
    return hit && NOTABLE.has(e.type);
  });
  return rel.sort((a, b) => new Date(a.ts) - new Date(b.ts));
}

function suspicious(e, alertEv) {
  return alertEv.has(e.id) || ['privilege_change', 'file_rename', 'shadow_copy_deleted', 'beacon', 'macro_exec', 'mailbox_rule_created', 'iam_attach_policy', 'create_access_key', 'put_bucket_acl', 'stop_logging', 'lateral_access'].includes(e.type) || (e.type === 'login_failed') || (e.type === 'login_success' && (e.details?.suspicious || e.details?.unusual));
}

function investigate(incident) {
  const evs = gather(incident);
  const alertEv = new Set(incident.alerts.flatMap((a) => a.evidence));
  const timeline = evs.map((e) => ({ ts: e.ts, eventId: e.id, phase: PHASE[e.type] || 'Other', summary: describe(e), suspicious: suspicious(e, alertEv), origin: e.origin, source: e.source }));

  // ---- Graph ----
  const nodes = new Map(), edges = [];
  const node = (id, kind, label, sus, evId) => { let n = nodes.get(id); if (!n) nodes.set(id, (n = { id, kind, label, suspicious: false, evidence: [] })); if (sus) n.suspicious = true; if (evId && !n.evidence.includes(evId)) n.evidence.push(evId); return n; };
  const susEvents = [];
  for (const e of evs) {
    const sus = suspicious(e, alertEv); if (!sus) continue;
    susEvents.push(e);
    const en = node('evt:' + e.id, 'event', e.type.replace(/_/g, ' '), true, e.id);
    en.ts = e.ts; en.summary = describe(e);
    const link = (id, kind, label, rel) => { node(id, kind, label, sus, e.id); edges.push({ from: id, to: en.id, label: rel, eventId: e.id, suspicious: true }); };
    if (e.user) link('user:' + e.user, 'user', e.user, 'actor');
    if (e.host) link('host:' + e.host, /^srv|^prod/.test(e.host) ? 'server' : 'device', e.host, 'on');
    if (e.ip && e.type !== 'process_start') link('ip:' + e.ip, 'ip', e.ip, e.type === 'outbound_conn' || e.type === 'beacon' ? 'dest' : 'source');
    if (e.domain) link('dom:' + e.domain, 'domain', e.domain, 'domain');
    if (e.resource && /^\//.test(e.resource)) link('file:' + e.resource, 'file', e.resource, 'accessed');
    else if (e.resource && ['iam_attach_policy', 'create_access_key', 'put_bucket_acl', 'stop_logging'].includes(e.type)) link('app:' + e.resource, 'application', e.resource, 'target');
    if (e.type === 'mailbox_rule_created' || e.type === 'api_call') link('app:' + (e.type === 'api_call' ? 'api-gateway' : 'mail-service'), 'application', e.type === 'api_call' ? 'api-gateway' : 'mail-service', 'target');
  }
  // Attack path = chain of suspicious events in time order (de-duplicated by phase+type to stay readable)
  const path = []; const seen = new Set();
  for (const e of susEvents) { const k = e.type + (e.host || e.user || ''); if (seen.has(k)) continue; seen.add(k); path.push('evt:' + e.id); }
  for (let i = 1; i < path.length; i++) edges.push({ from: path[i - 1], to: path[i], label: 'then', suspicious: true, path: true });

  // ---- Techniques: merge alert-level MITRE mappings; never upgrade a hypothesis without evidence ----
  const tm = new Map();
  for (const a of incident.alerts) for (const t of a.mitre || []) {
    const cur = tm.get(t.id);
    const status = t.status === 'indicated' ? 'evidence-supported' : 'hypothesis';
    if (!cur || (cur.status === 'hypothesis' && status === 'evidence-supported')) tm.set(t.id, { id: t.id, name: t.name, status, basis: status === 'evidence-supported' ? `Rule ${a.rule}: ${a.evidenceSummary}` : `Plausible given ${a.rule}; no direct proof yet`, evidence: a.evidence });
  }
  const techniques = [...tm.values()];

  // ---- Findings: confirmed (direct log facts) vs hypotheses ----
  const confirmed = incident.alerts.map((a) => ({ statement: a.evidenceSummary, evidence: a.evidence, rule: a.rule }));
  const hypotheses = [];
  const has = (r) => incident.alerts.some((a) => a.rule === r);
  const hasType = (t) => evs.some((e) => e.type === t);
  if (has('R-CRED-COMPROMISE')) hypotheses.push({ statement: 'The account was taken over by an external party after a successful guess/stuffing attack.', confidence: 'medium', toConfirm: 'Confirm with user out-of-band; check for activity from the same IP on other accounts.' });
  if (has('R-ANOMALOUS-LOGIN') && !has('R-CRED-COMPROMISE')) hypotheses.push({ statement: 'Login may be legitimate travel (known device + MFA) or session theft.', confidence: 'low', toConfirm: 'Verify with the user; check device posture.' });
  if (has('R-MASS-DOWNLOAD') || has('R-EXFIL')) hypotheses.push({ statement: 'Data left the environment.', confidence: has('R-EXFIL') ? 'medium' : 'low', toConfirm: has('R-EXFIL') ? 'Outbound transfer observed; confirm content via DLP/packet capture.' : 'Download observed but no outbound transfer evidence yet; check egress logs.' });
  if (has('R-RANSOMWARE')) hypotheses.push({ statement: 'Encryption may be spreading to reachable file shares.', confidence: 'medium', toConfirm: 'Review SMB sessions from the infected host.' });
  if (has('R-PHISH-CLICK') && has('R-MACRO')) hypotheses.push({ statement: 'Phishing link led to payload delivery and execution.', confidence: 'medium', toConfirm: 'Retrieve the delivered file and detonate in sandbox.' });
  if (has('R-TOKEN-REUSE')) hypotheses.push({ statement: 'Session token was stolen (e.g. via phishing proxy) and replayed.', confidence: 'medium', toConfirm: 'Correlate token issuance with the phishing click; review token provenance.' });
  if (has('R-CLOUD-ADMIN') || has('R-CLOUD-BLIND')) hypotheses.push({ statement: 'Cloud identity is being abused to gain persistence and hide activity.', confidence: has('R-CLOUD-BLIND') ? 'medium' : 'low', toConfirm: 'Review all actions by this principal in the last 24h; check key provenance.' });
  if (!hypotheses.length) hypotheses.push({ statement: 'Activity may be benign.', confidence: 'medium', toConfirm: 'Verify with the asset owner.' });

  // ---- Entry point (only when the evidence supports it) ----
  const first = susEvents[0];
  const entry = first ? { eventId: first.id, description: describe(first), phase: PHASE[first.type], basis: has('R-CRED-COMPROMISE') || has('R-PHISH-CLICK') || has('R-TOKEN-REUSE') ? 'evidence-supported' : 'inferred-earliest-event', note: has('R-CRED-COMPROMISE') ? 'Brute-force sequence followed by success from same source.' : 'Earliest anomalous event in the correlated set; not proof of root cause.' } : { basis: 'unknown', description: 'Insufficient evidence' };

  // ---- Scope ----
  const A = incident.entities, resSet = new Set([...A.resources, ...evs.filter((e) => e.resource?.startsWith('/')).map((e) => e.resource)]);
  const affectedAssets = [
    ...A.users.map((u) => ({ type: 'user', id: u, status: 'suspected-compromised' })),
    ...A.hosts.map((h) => ({ type: 'host', id: h, status: incident.alerts.some((a) => a.rule === 'R-RANSOMWARE' && a.affected.hosts.includes(h)) ? 'confirmed-impacted' : 'suspected' })),
    ...[...resSet].map((r) => ({ type: 'resource', id: r, status: 'accessed' })),
    ...(evs.filter((e) => e.type === 'iam_attach_policy' || e.type === 'put_bucket_acl').map((e) => ({ type: 'cloud', id: e.resource, status: 'modified' }))),
  ];
  const sev = Math.max(...incident.alerts.map((a) => a.riskScore));
  const kinds = new Set(timeline.filter((t) => t.suspicious).map((t) => t.phase));
  const confidence = incident.alerts.length >= 3 && kinds.size >= 3 ? 'high' : incident.alerts.length >= 2 || kinds.size >= 2 ? 'medium' : 'low';

  const categories = [...new Set(incident.alerts.map((a) => a.category))];
  const response = [...new Set(incident.alerts.map((a) => a.recommendedAction))];
  const summary = `${categories.join(' + ')}: ${incident.alerts.length} correlated alert(s) across ${A.users.length} user(s), ${A.hosts.length} host(s), ${A.ips.length} IP(s). Peak risk ${sev}/100. ${entry.basis === 'unknown' ? '' : 'Earliest anomalous activity: ' + entry.description + '.'} ${timeline.filter((t) => t.suspicious).length} suspicious events in timeline; ${techniques.filter((t) => t.status === 'evidence-supported').length} technique(s) evidence-supported, ${techniques.filter((t) => t.status === 'hypothesis').length} hypothesised.`;
  const out = { incidentId: incident.id, summary, timeline, evidence: confirmed, confirmedFindings: confirmed, hypotheses, affectedAssets, techniques, entryPoint: entry, confidence, confidenceReason: `${incident.alerts.length} alert(s) spanning ${kinds.size} kill-chain phase(s)`, recommendedResponse: response, graph: { nodes: [...nodes.values()], edges, attackPath: path }, aiNarrative: null };
  const v = validate(SPECS.investigation, out, 'investigation'); if (!v.ok) throw new Error('INVESTIGATOR invalid output: ' + v.errors.join('; '));
  return out;
}

// Adjust with threat-intel results: only malicious verdicts raise confidence; unknown never does.
function refine(inv, intel) {
  const map = new Map(intel.indicators.map((i) => [i.indicator, i]));
  for (const n of inv.graph.nodes) { const key = n.id.replace(/^(ip|dom):/, ''); const i = map.get(key); if (i) n.intel = { verdict: i.verdict, source: i.source, tags: i.tags }; if (i?.verdict === 'malicious') n.suspicious = true; }
  const mal = intel.indicators.filter((i) => i.verdict === 'malicious');
  if (mal.length && inv.confidence !== 'high') { inv.confidence = 'high'; inv.confidenceReason += `; ${mal.length} indicator(s) matched known-malicious intel`; }
  return inv;
}

async function narrate(inv) {
  if (!process.env.ANTHROPIC_API_KEY) return;
  try {
    const facts = { summary: inv.summary, confirmed: inv.confirmedFindings.map((f) => f.statement), hypotheses: inv.hypotheses.map((h) => h.statement), techniques: inv.techniques };
    const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', signal: AbortSignal.timeout(15000), headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5', max_tokens: 300, messages: [{ role: 'user', content: 'Write a 3-sentence plain-English briefing for a SOC manager using ONLY these structured facts. Keep "confirmed" and "hypothesis" distinct; do not add facts.\n' + JSON.stringify(facts) }] }) });
    if (r.ok) inv.aiNarrative = { text: (await r.json()).content?.[0]?.text, model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5', note: 'AI-generated prose over the structured facts above; not evidence.' };
  } catch { /* narrative is optional */ }
}
module.exports = { investigate, refine, narrate, describe };

// Static analysis of a user-reported email. URLs are NEVER fetched/opened — only parsed.
const CORP = ['corp-sim.example', 'office-sim.example'];
function lev(a, b) { const m = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]); for (let j = 1; j <= b.length; j++) m[0][j] = j; for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) m[i][j] = Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); return m[a.length][b.length]; }
function analyzeEmail(d) {
  const urls = [...new Set((d.body || '').match(/https?:\/\/[^\s)>"']+/gi) || [])];
  const domains = [...new Set(urls.map((u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return null; } }).filter(Boolean))];
  const flags = [];
  const fromDom = (d.from || '').split('@')[1]?.toLowerCase();
  if (fromDom && !CORP.includes(fromDom)) flags.push(`Sender domain ${fromDom} is external`);
  if (d.replyTo && d.replyTo !== d.from) flags.push('Reply-To differs from From');
  if (/urgent|immediately|within 24|suspend|verify your|password expires|payroll/i.test(`${d.subject} ${d.body}`)) flags.push('Urgency / credential-themed language');
  for (const dm of domains) { if (/login|secure|payroll|verify|account/.test(dm)) flags.push(`${dm}: credential-themed hostname`); for (const c of CORP) if (lev(dm.replace(/\.[a-z]+$/, ''), c.replace(/\.[a-z]+$/, '')) <= 3 && dm !== c) flags.push(`${dm}: lookalike of ${c}`); }
  return { urls, domains, flags, urlsFetched: false, note: 'Static analysis only: no URL was opened or fetched.' };
}
module.exports.analyzeEmail = analyzeEmail;
