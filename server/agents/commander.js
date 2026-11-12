'use strict';
const rzBlast = require('../resilience/blast'), rzMem = require('../resilience/memory'), rzLeak = require('../resilience/leak');
// COMMANDER — central orchestrator. Owns the incident state machine and the 12-stage response workflow.
// Agents talk to it ONLY through schema-validated JSON; a failing agent degrades the incident but never stops it.
const { uid, sleep, sha256, clamp } = require('../core/util');
const bus = require('../core/bus');
const audit = require('../core/audit');
const events = require('../core/events');
const sim = require('../sim/enterprise');
const sentinel = require('./sentinel');
const investigator = require('./investigator');
const oracle = require('./oracle');
const guardian = require('./guardian');
const recovery = require('./recovery');
const kb = require('./kb');
const notifications = require('../integrations/notifications');
const ticketing = require('../integrations/ticketing');

const cfg = require('../core/config');
const autonomy = require('../core/autonomy');
const settings = { paceMs: cfg.paceMs, autopilot: false, correlateMs: cfg.correlateMs, approvalTimeoutMin: cfg.approvalTimeoutMin };
const incidents = new Map();
let seq = 1000;
const messages = [];
const agentStats = Object.fromEntries(['SENTINEL', 'INVESTIGATOR', 'ORACLE', 'GUARDIAN', 'RECOVERY', 'COMMANDER'].map((a) => [a, { runs: 0, failures: 0, state: 'idle', last: null, lastMs: 0 }]));
const executions = [];

const STAGES = [
  ['receive', 'Receive security events', 'SENTINEL'], ['group', 'Group events into incident', 'COMMANDER'], ['risk', 'Calculate risk score', 'COMMANDER'],
  ['investigate', 'Investigate incident', 'INVESTIGATOR'], ['enrich', 'Enrich indicators', 'ORACLE'], ['assets', 'Determine affected assets & priority', 'COMMANDER'],
  ['plan', 'Generate containment recommendations', 'GUARDIAN'], ['authorize', 'Request authorization', 'COMMANDER'], ['execute', 'Execute approved actions', 'GUARDIAN'],
  ['recovery', 'Generate & run recovery tasks', 'RECOVERY'], ['verify', 'Verify recovery', 'RECOVERY'], ['report', 'Produce final incident report', 'COMMANDER'],
];
const TRANSITIONS = { DETECTED: ['TRIAGED'], TRIAGED: ['INVESTIGATING', 'MONITORING'], MONITORING: ['RESOLVED'], INVESTIGATING: ['ENRICHING'], ENRICHING: ['PLANNING'], PLANNING: ['AWAITING_APPROVAL', 'CONTAINING', 'RECOVERING'], AWAITING_APPROVAL: ['CONTAINING'], CONTAINING: ['RECOVERING'], RECOVERING: ['VERIFYING'], VERIFYING: ['RESOLVED', 'RECOVERING'], RESOLVED: ['CLOSED'], CLOSED: [] };
const AUTO_STATUS = { DETECTED: 'Open', TRIAGED: 'In Progress', MONITORING: 'Monitoring', INVESTIGATING: 'In Progress', ENRICHING: 'In Progress', PLANNING: 'In Progress', AWAITING_APPROVAL: 'Awaiting Approval', CONTAINING: 'Containing', RECOVERING: 'Recovering', VERIFYING: 'Recovering', RESOLVED: 'Resolved', CLOSED: 'Closed' };

const RULE_WHY = {
  'R-BRUTE': 'Five or more failed logins for one account in five minutes is the classic signature of password guessing.',
  'R-SPRAY': 'One source failing against many accounts indicates password spraying.',
  'R-CRED-COMPROMISE': 'A successful login that follows a burst of failures means the guessing may have succeeded.',
  'R-ANOMALOUS-LOGIN': 'Login geography/device/time deviates from the user baseline.',
  'R-PRIV': 'Privilege change made without an approved change ticket by an authorised admin.',
  'R-MASS-DOWNLOAD': 'Volume of files/bytes accessed in 10 minutes far exceeds normal behaviour.',
  'M-ZSCORE-DL': 'Statistical model: transfer size is >4 standard deviations above the user\'s learned baseline.',
  'R-EXFIL': 'Large outbound transfer to an external address.', 'R-BEACON': 'Fixed-interval low-volume connections to one external host resemble malware check-ins.',
  'R-RANSOMWARE': 'Dozens of files renamed to an encrypted extension within a minute is ransomware behaviour.', 'R-SHADOW-DEL': 'Deleting shadow copies prevents recovery and is a ransomware precursor.',
  'R-PHISH-CLICK': 'User visited a very recently registered domain.', 'R-MACRO': 'An Office application spawning a script interpreter is a common malware execution chain.',
  'R-TOKEN-REUSE': 'The same token is being used from a geography different from where it was first seen.', 'R-MAIL-FWD': 'Auto-forward rule to an external address is used to silently collect mail.',
  'R-PHISH-REPORT': 'A user reported the message as suspicious.', 'R-CLOUD-ADMIN': 'Administrator privileges were attached to a role outside change control.', 'R-CLOUD-KEY': 'A new long-lived access key can provide persistence.',
  'R-CLOUD-PUBLIC': 'Storage was made publicly readable.', 'R-CLOUD-BLIND': 'Stopping audit logging is a defence-evasion technique.', 'R-API-ENUM': 'Burst of API errors suggests enumeration.',
};

function msg(inc, from, to, type, payload) {
  const m = { id: uid('msg'), ts: new Date().toISOString(), incidentId: inc?.id || null, from, to, type, payload };
  if (from === 'COMMANDER') { agentStats.COMMANDER.runs++; agentStats.COMMANDER.last = m.ts; }
  messages.push(m); if (messages.length > 500) messages.shift(); if (inc) inc.messages.push(m);
  bus.emit('agent_msg', m); return m;
}
async function runAgent(inc, agent, label, fn, fallback) {
  const st = agentStats[agent], t0 = Date.now(); st.state = 'working'; st.current = label; st.runs++; bus.emit('agents', agentStats);
  const ex = { id: uid('exe'), incidentId: inc.id, agent, label, startedAt: new Date(t0).toISOString(), status: 'running' }; executions.push(ex);
  try { const r = await fn(); ex.status = 'ok'; return r; }
  catch (e) {
    st.failures++; ex.status = 'failed'; ex.error = e.message; inc.degraded = true;
    audit.log(agent, 'AGENT_FAILED', { label, error: e.message }, inc.id); msg(inc, agent, 'COMMANDER', 'error', { label, error: e.message, fallback: !!fallback });
    return fallback ? fallback(e) : null;
  } finally { ex.endedAt = new Date().toISOString(); st.state = 'idle'; st.current = null; st.last = ex.endedAt; st.lastMs = Date.now() - t0; bus.emit('agents', agentStats); }
}
const pub = (inc) => bus.emit('incident', inc);
function setState(inc, to, why) {
  if (inc.state === to) return;
  if (!TRANSITIONS[inc.state]?.includes(to)) throw new Error(`illegal transition ${inc.state} → ${to}`);
  audit.log('COMMANDER', 'STATE_TRANSITION', { from: inc.state, to, why }, inc.id);
  inc.stateHistory.push({ from: inc.state, to, ts: new Date().toISOString(), why }); inc.state = to;
  if (!inc.statusLocked) inc.status = AUTO_STATUS[to]; pub(inc);
}
function stage(inc, key, status, note) {
  const s = inc.workflow.find((x) => x.key === key); s.status = status; if (note) s.note = note; s[status === 'running' ? 'startedAt' : 'endedAt'] = new Date().toISOString(); pub(inc);
}
const pace = (m = 1) => sleep(settings.paceMs * m);

// ---------- Risk prioritisation (explainable) ----------
const CRIT = { low: 20, medium: 50, high: 75, critical: 100 };
function prioritize(inc) {
  const A = inc.alerts, ent = inc.entities;
  const sev = Math.max(...A.map((a) => a.riskScore));
  const conf = { low: 30, medium: 60, high: 90 }[inc.investigation?.confidence || 'low'];
  const roleW = { cfo: 80, sysadmin: 90, 'hr-lead': 60 };
  const asset = Math.max(30, ...ent.hosts.map((h) => CRIT[sim.env.hosts[h]?.criticality] || 20), ...ent.users.map((u) => roleW[sim.env.users[u]?.role] || 30), ...(A.some((a) => a.rule === 'R-CLOUD-ADMIN') ? [75] : []));
  const ext = A.some((a) => a.affected.ips.some((ip) => !/^(10\.|192\.168\.)/.test(ip)) && ['R-BRUTE', 'R-CRED-COMPROMISE', 'R-EXFIL', 'R-BEACON', 'R-TOKEN-REUSE', 'R-SPRAY'].includes(a.rule));
  const exposure = A.some((a) => a.rule === 'R-CLOUD-PUBLIC') ? 90 : ext ? 75 : 40;
  const impact = A.some((a) => a.rule === 'R-RANSOMWARE') ? 100 : A.some((a) => a.rule === 'R-EXFIL') ? 90 : A.some((a) => a.rule === 'R-MASS-DOWNLOAD') ? 80 : A.some((a) => ['R-PRIV', 'R-CLOUD-ADMIN', 'R-CLOUD-BLIND'].includes(a.rule)) ? 75 : 40;
  const spread = clamp(25 * (ent.hosts.length + ent.users.length + ent.resources.length), 0, 100);
  const factors = [['Severity (peak alert risk)', sev, 0.30], ['Confidence', conf, 0.15], ['Asset importance', asset, 0.20], ['Exposure', exposure, 0.10], ['Potential impact', impact, 0.15], ['Spread (affected systems)', spread, 0.10]];
  const score = Math.round(factors.reduce((s, [, v, w]) => s + v * w, 0));
  const priority = sev < 40 ? 'P4' : score >= 78 ? 'P1' : score >= 62 ? 'P2' : score >= 45 ? 'P3' : 'P4';
  return { score, priority, factors: factors.map(([name, value, weight]) => ({ name, value: Math.round(value), weight })) };
}
const sevOf = (r) => (r >= 85 ? 'critical' : r >= 65 ? 'high' : r >= 40 ? 'medium' : 'low');

function explainAlert(a) {
  const conf = a.model === 'zscore' ? 0.6 : a.evidence.length >= 5 ? 0.9 : a.evidence.length >= 2 ? 0.8 : 0.65;
  return { whatHappened: a.evidenceSummary, whyFlagged: RULE_WHY[a.rule] || 'Rule match', evidence: a.evidence, confidence: conf, detection: a.model === 'zscore' ? 'anomaly model (z-score)' : 'rule', recommended: a.recommendedAction };
}

// ---------- Alert intake & correlation ----------
const shares = (inc, a) => ['users', 'hosts', 'ips', 'domains', 'hashes'].some((k) => a.affected[k].some((x) => inc.entities[k].includes(x)));
function mergeEntities(inc, a) { for (const k of ['users', 'hosts', 'ips', 'resources', 'domains', 'hashes']) for (const x of a.affected[k] || []) if (!inc.entities[k].includes(x)) inc.entities[k].push(x); }

function receiveAlert(alert) {
  agentStats.SENTINEL.runs++; agentStats.SENTINEL.last = new Date().toISOString(); bus.emit('alert', alert);
  audit.log('SENTINEL', 'ALERT_RAISED', { id: alert.id, rule: alert.rule, risk: alert.riskScore, severity: alert.severity }, null);
  const open = [...incidents.values()].find((i) => !['RESOLVED', 'CLOSED'].includes(i.state) && Date.now() - new Date(i.createdAt) < 3600e3 && shares(i, alert));
  if (open) {
    open.alerts.push(alert); mergeEntities(open, alert); alert.explain = explainAlert(alert);
    open.riskScore = Math.max(open.riskScore, alert.riskScore); open.severity = sevOf(open.riskScore);
    if (open.containedAt) open.postContainmentAlerts++;
    freezeEvidence(open); audit.log('COMMANDER', 'ALERT_CORRELATED', { alert: alert.id, rule: alert.rule }, open.id);
    msg(open, 'COMMANDER', 'COMMANDER', 'correlation', { alert: alert.id, merged: true }); pub(open); return open;
  }
  return create(alert);
}

function freezeEvidence(inc) {
  const items = events.byIds(inc.alerts.flatMap((a) => a.evidence)).map((e) => ({ ...e }));
  inc.evidence = { preservedAt: new Date().toISOString(), count: items.length, sha256: sha256(items), items };
}
function create(alert) {
  const id = 'INC-' + ++seq;
  const inc = { id, title: '', createdAt: new Date().toISOString(), state: 'DETECTED', status: 'Open', statusLocked: false, stateHistory: [], alerts: [alert], entities: { users: [], hosts: [], ips: [], resources: [], domains: [], hashes: [] }, riskScore: alert.riskScore, severity: alert.severity, priority: 'P3', priorityBreakdown: null,
    workflow: STAGES.map(([key, label, agent]) => ({ key, label, agent, status: 'pending' })), messages: [], investigation: null, intel: null, plan: null, containment: [], approvals: [], recovery: { readiness: [], tasks: [] }, verification: null, report: null,
    notes: [], analyst: null, ticket: null, notifications: [], playbooks: [], lessons: [], disposition: 'respond', postContainmentAlerts: 0, degraded: false, origin: alert.origin, scenarioId: alert.scenarioId, timing: { detectedAt: new Date().toISOString() }, emailAnalysis: null };
  mergeEntities(inc, alert); alert.explain = explainAlert(alert); freezeEvidence(inc);
  inc.title = `${alert.category} — ${alert.affected.users[0] || alert.affected.hosts[0] || alert.affected.ips[0] || 'unknown'}`;
  incidents.set(id, inc);
  audit.log('COMMANDER', 'INCIDENT_CREATED', { title: inc.title, firstAlert: alert.id, evidenceHash: inc.evidence.sha256.slice(0, 16) }, id);
  msg(inc, 'SENTINEL', 'COMMANDER', 'alert', { alertId: alert.id, rule: alert.rule, risk: alert.riskScore, severity: alert.severity });
  stage(inc, 'receive', 'done', `${alert.rule}`); stage(inc, 'group', 'done', 'Incident opened'); pub(inc);
  runPipeline(inc).catch((e) => { audit.log('COMMANDER', 'PIPELINE_CRASH_CONTAINED', { error: e.message }, id); inc.degraded = true; inc.pipelineError = e.message; pub(inc); });
  return inc;
}

// ---------- Approval handling ----------
const pending = new Map(); // actionId -> {resolve, inc}
function requestApproval(inc, action) {
  action.status = 'pending_approval'; msg(inc, 'GUARDIAN', 'COMMANDER', 'approval_request', { action: action.id, type: action.type, target: action.target });
  audit.log('COMMANDER', 'APPROVAL_REQUESTED', { id: action.id, type: action.type, target: action.target }, inc.id); bus.emit('approval', { incidentId: inc.id, action });
  const p = new Promise((resolve) => pending.set(action.id, { resolve, inc }));
  if (settings.approvalTimeoutMin > 0) { const t = setTimeout(() => { if (pending.has(action.id)) { decide(action.id, false, 'system', `Expired after ${settings.approvalTimeoutMin} min with no decision (fail-safe: not executed)`).catch(() => {}); } }, settings.approvalTimeoutMin * 60e3); t.unref?.(); }
  if (settings.autopilot) setTimeout(() => decide(action.id, true, 'autopilot', 'Auto-approved (autopilot demo mode)').catch(() => {}), settings.paceMs * 1.5);
  return p;
}
async function decide(actionId, approve, by, comment = '') {
  const p = pending.get(actionId); if (!p) throw new Error('no pending approval for ' + actionId);
  const { inc } = p, action = inc.containment.find((a) => a.id === actionId); pending.delete(actionId);
  const rec = { actionId, decision: approve ? 'approved' : 'rejected', by, ts: new Date().toISOString(), comment, description: action.description }; inc.approvals.push(rec);
  audit.log(by, approve ? 'ACTION_APPROVED' : 'ACTION_REJECTED', { id: actionId, type: action.type, comment }, inc.id);
  if (!approve) action.status = 'denied'; else action.status = 'approved'; action.approvedBy = approve ? by : null;
  pub(inc); p.resolve(rec); return rec;
}
const pendingFor = () => [...pending.entries()].map(([id, p]) => ({ incidentId: p.inc.id, action: p.inc.containment.find((a) => a.id === id) }));

// ---------- Recovery signalling ----------
const waiters = new Map();
const signal = (inc) => { const w = waiters.get(inc.id); if (w) { waiters.delete(inc.id); w(); } };
const waitSignal = (inc) => new Promise((r) => waiters.set(inc.id, r));
// Skip a step that is not a necessity (or Disallow a gated AI step: the block simply stays in place).
async function skipTask(incId, taskId, by) {
  const inc = incidents.get(incId), t = inc?.recovery.tasks.find((x) => x.id === taskId); if (!t) throw new Error('task not found');
  if (t.status !== 'pending') throw new Error('step is already ' + t.status);
  if (!t.optional && t.gate !== 'allow') throw new Error('this step is required and cannot be skipped');
  t.status = 'skipped'; t.completedAt = new Date().toISOString(); t.completedBy = by; audit.log(by, t.gate === 'allow' ? 'TASK_DISALLOWED' : 'TASK_SKIPPED', { task: t.title }, inc.id); pub(inc); signal(inc); return t;
}
// "Check it": the AI verifies a human step itself (e.g. asks Okta/Entra whether the password changed) and continues if it is done.
async function checkTask(incId, taskId, by = 'AI') {
  const inc = incidents.get(incId), t = inc?.recovery.tasks.find((x) => x.id === taskId); if (!t) throw new Error('task not found');
  if (t.status !== 'pending') return { known: true, done: t.status === 'done', detail: 'step is already ' + t.status };
  const r = await recovery.checkTask(t, inc); t.lastCheck = { at: new Date().toISOString(), ...r };
  if (r.known && r.done) { await completeTask(incId, taskId, 'AI:verified'); audit.log('RECOVERY', 'TASK_AUTO_VERIFIED', { task: t.title, detail: r.detail }, inc.id); } else pub(inc);
  return r;
}
async function sweepChecks() { let n = 0; for (const inc of incidents.values()) for (const t of inc.recovery?.tasks || []) if (t.checkable && t.status === 'pending' && (t.dependsOn || []).every((d) => ['done', 'skipped'].includes(inc.recovery.tasks.find((x) => x.id === d)?.status))) { try { const r = await checkTask(inc.id, t.id); if (r.done) n++; } catch { /* next time */ } } return n; }
async function completeTask(incId, taskId, by) {
  const inc = incidents.get(incId), t = inc?.recovery.tasks.find((x) => x.id === taskId); if (!t) throw new Error('task not found');
  if (t.status === 'done') return t;
  const deps = (t.dependsOn || []).map((d) => inc.recovery.tasks.find((x) => x.id === d)); if (deps.some((d) => !['done', 'skipped'].includes(d.status))) throw new Error('an earlier step is not finished yet');
  try { await recovery.runTask(t, inc, by); } catch (e) { t.status = 'failed'; t.error = e.message; audit.log(by, 'TASK_FAILED', { task: t.title, error: e.message }, inc.id); }
  audit.log(by, 'TASK_COMPLETED', { task: t.title, status: t.status }, inc.id); pub(inc); signal(inc); return t;
}

// ---------- The 12-stage pipeline ----------
async function runPipeline(inc) {
  for (let n = -1, loops = 0; n !== inc.alerts.length && loops < 8; loops++) { n = inc.alerts.length; await sleep(settings.correlateMs); } // quiet-period correlation: wait until no new related alert arrives
  // 3. risk
  stage(inc, 'risk', 'running'); setState(inc, 'TRIAGED', 'risk scored');
  const pre = prioritize(inc); inc.riskScore = Math.max(...inc.alerts.map((a) => a.riskScore)); inc.severity = sevOf(inc.riskScore); inc.priority = pre.priority; inc.priorityBreakdown = pre;
  if (inc.riskScore < 40) inc.disposition = 'monitor';
  msg(inc, 'COMMANDER', 'COMMANDER', 'triage', { risk: inc.riskScore, priority: inc.priority, disposition: inc.disposition });
  stage(inc, 'risk', 'done', `risk ${inc.riskScore}/100 → ${inc.priority}${inc.disposition === 'monitor' ? ' (monitor only)' : ''}`); await pace();

  if (inc.disposition === 'monitor') setState(inc, 'MONITORING', 'low risk, no containment warranted');
  else setState(inc, 'INVESTIGATING', 'dispatch INVESTIGATOR');

  // 4. investigate
  stage(inc, 'investigate', 'running'); msg(inc, 'COMMANDER', 'INVESTIGATOR', 'task', { incident: inc.id, alerts: inc.alerts.map((a) => a.id) });
  inc.investigation = await runAgent(inc, 'INVESTIGATOR', 'Correlate events & build timeline', async () => {
    const r = investigator.investigate(inc);
    const mail = events.byIds(inc.alerts.flatMap((a) => a.evidence)).find((e) => e.type === 'email_reported');
    if (mail) { inc.mailRecipients = mail.details.recipients || []; inc.emailAnalysis = investigator.analyzeEmail(mail.details); const clickers = events.all().filter((e) => e.type === 'email_link_click' && inc.emailAnalysis.domains.includes(e.domain)).map((e) => e.user); inc.emailAnalysis.clickers = [...new Set(clickers)]; inc.emailAnalysis.recipients = mail.details.recipients || []; for (const u of clickers) { if (!inc.entities.users.includes(u)) inc.entities.users.push(u); } for (const d of inc.emailAnalysis.domains) if (!inc.entities.domains.includes(d)) inc.entities.domains.push(d); freezeEvidence(inc); }
    return r;
  }, (e) => ({ incidentId: inc.id, summary: `FALLBACK (INVESTIGATOR unavailable: ${e.message}). Alerts only: ${inc.alerts.map((a) => a.evidenceSummary).join(' | ')}`, timeline: inc.alerts.map((a) => ({ ts: a.ts, summary: a.evidenceSummary, phase: 'Unknown', suspicious: true })), evidence: inc.alerts.map((a) => ({ statement: a.evidenceSummary, evidence: a.evidence })), confirmedFindings: [], affectedAssets: [], techniques: inc.alerts.flatMap((a) => a.mitre.map((m) => ({ ...m, status: 'hypothesis', basis: 'fallback' }))), confidence: 'low', recommendedResponse: inc.alerts.map((a) => a.recommendedAction), graph: { nodes: [], edges: [], attackPath: [] }, hypotheses: [], entryPoint: { basis: 'unknown' } }));
  if (inc.emailAnalysis && inc.investigation) {
    inc.investigation.emailAnalysis = inc.emailAnalysis;
    const A = inc.investigation.affectedAssets;
    for (const a of A) if (a.type === 'user') a.status = inc.emailAnalysis.clickers.includes(a.id) ? 'clicked-phishing-link' : 'reporter';
    for (const r of inc.emailAnalysis.recipients) if (!A.some((a) => a.type === 'user' && a.id === r)) A.push({ type: 'user', id: r, status: 'recipient (no click observed)' });
  }
  msg(inc, 'INVESTIGATOR', 'COMMANDER', 'investigation', { confidence: inc.investigation.confidence, timeline: inc.investigation.timeline.length, techniques: inc.investigation.techniques.map((t) => `${t.id}:${t.status}`) });
  if (inc.alerts.some(rzLeak.isLeak)) rzLeak.forIncident(inc, 'COMMANDER').then((l) => { if (l) { inc.leak = l; msg(inc, 'INVESTIGATOR', 'COMMANDER', 'leak_response', { secret: l.secretType, matched: l.matched.length, plan: l.planId || null }); pub(inc); } }).catch((e) => audit.log('COMMANDER', 'RZ_HOOK_FAILED', { error: e.message }, inc.id));
  try { inc.blast = rzBlast.forIncident(inc); if (inc.blast) { inc.investigation.blast = inc.blast; msg(inc, 'INVESTIGATOR', 'COMMANDER', 'blast_radius', { affected: inc.blast.counts.total, deployments: inc.blast.connectedDeployments }); } inc.similar = rzMem.similar(inc); if (inc.similar.length) msg(inc, 'ORACLE', 'COMMANDER', 'similar_incidents', { matches: inc.similar.map((x) => `${x.incidentId}:${x.similarity}%`) }); } catch (e) { audit.log('COMMANDER', 'RZ_HOOK_FAILED', { error: e.message }, inc.id); }
  investigator.narrate(inc.investigation).then(() => pub(inc));
  inc.investigation.alertCount = inc.alerts.length;
  stage(inc, 'investigate', 'done', `${inc.investigation.timeline.length} events, confidence ${inc.investigation.confidence}`); if (inc.state === 'INVESTIGATING') setState(inc, 'ENRICHING', 'investigation complete'); await pace();

  // 5. enrich
  stage(inc, 'enrich', 'running'); msg(inc, 'COMMANDER', 'ORACLE', 'task', { indicators: inc.entities.ips.length + inc.entities.domains.length + inc.entities.hashes.length });
  inc.intel = await runAgent(inc, 'ORACLE', 'Enrich indicators', () => oracle.enrich(inc.entities), (e) => ({ indicators: [], relatedPatterns: [], summary: `Threat intel unavailable (${e.message}); indicators NOT assessed.` }));
  investigator.refine(inc.investigation, inc.intel);
  msg(inc, 'ORACLE', 'COMMANDER', 'intel', { summary: inc.intel.summary, malicious: inc.intel.indicators.filter((i) => i.verdict === 'malicious').map((i) => i.indicator) });
  stage(inc, 'enrich', 'done', inc.intel.summary); if (inc.state === 'ENRICHING') setState(inc, 'PLANNING', 'intel attached'); await pace();

  // 6. assets & priority & knowledge
  stage(inc, 'assets', 'running');
  inc.priorityBreakdown = prioritize(inc); inc.priority = inc.disposition === 'monitor' ? 'P4' : inc.priorityBreakdown.priority; inc.timing.investigatedAt = new Date().toISOString();
  inc.playbooks = kb.search(inc.alerts.map((a) => a.category + ' ' + a.evidenceSummary).join(' ') + ' ' + inc.investigation.techniques.map((t) => t.name).join(' ')).map(({ id, title, text, score }) => ({ id, title, excerpt: text.slice(0, 240) + '…', score }));
  msg(inc, 'COMMANDER', 'COMMANDER', 'priority', { priority: inc.priority, score: inc.priorityBreakdown.score, playbooks: inc.playbooks.map((p) => p.id) });
  stage(inc, 'assets', 'done', `${inc.investigation.affectedAssets.length} assets · ${inc.priority} (score ${inc.priorityBreakdown.score})`); audit.log('COMMANDER', 'PRIORITY_SET', { priority: inc.priority, breakdown: inc.priorityBreakdown.factors }, inc.id);
  if (['P1', 'P2'].includes(inc.priority) || inc.severity === 'critical') notifications.notify(inc, `[PHOENIX X] ${inc.priority} ${inc.severity.toUpperCase()}: ${inc.title}`, `${inc.id}\n${inc.investigation.summary}\nPriority score ${inc.priorityBreakdown.score}/100`, ['slack', 'email', 'sms']).then((n) => { inc.notifications.push(...n); pub(inc); });
  if (inc.priority !== 'P4' || inc.alerts.some((a) => a.rule === 'R-PHISH-REPORT')) ticketing.create(inc).then((t) => { inc.ticket = t; pub(inc); });
  await pace();

  if (inc.investigation.alertCount !== inc.alerts.length && !inc.investigation.fallback) { // alerts merged after investigation started: refresh so plan sees everything
    const fresh = await runAgent(inc, 'INVESTIGATOR', 'Refresh investigation with late alerts', () => investigator.investigate(inc)); if (fresh) { inc.investigation = fresh; inc.investigation.alertCount = inc.alerts.length; inc.intel = await runAgent(inc, 'ORACLE', 'Re-enrich indicators', () => oracle.enrich(inc.entities), () => inc.intel); investigator.refine(inc.investigation, inc.intel); if (inc.emailAnalysis) inc.investigation.emailAnalysis = inc.emailAnalysis; inc.priorityBreakdown = prioritize(inc); inc.priority = inc.disposition === 'monitor' ? 'P4' : inc.priorityBreakdown.priority; msg(inc, 'COMMANDER', 'INVESTIGATOR', 'refresh', { alerts: inc.alerts.length }); pub(inc); }
  }
  // 7. plan
  stage(inc, 'plan', 'running'); msg(inc, 'COMMANDER', 'GUARDIAN', 'task', { priority: inc.priority });
  const plan = await runAgent(inc, 'GUARDIAN', 'Prepare containment plan', () => guardian.plan(inc, inc.investigation, inc.intel), () => ({ incidentId: inc.id, actions: [], manualOnly: [], note: 'GUARDIAN unavailable — manual containment required' }));
  inc.plan = plan; inc.containment = plan.actions; msg(inc, 'GUARDIAN', 'COMMANDER', 'plan', { note: plan.note, actions: plan.actions.map((a) => `${a.type}[${a.tier}]`), manualOnly: plan.manualOnly.map((m) => m.type) });
  stage(inc, 'plan', 'done', plan.note); await pace();

  // 8. authorize (+ 9. execute automatic ones concurrently)
  const autos = inc.containment.filter((a) => a.tier === 'automatic'), needs = inc.containment.filter((a) => a.tier === 'approval');
  if (inc.containment.length) {
    if (needs.length) { stage(inc, 'authorize', 'running', `${needs.length} action(s) need human approval`); setState(inc, 'AWAITING_APPROVAL', 'approval-tier actions pending'); }
    else stage(inc, 'authorize', 'done', 'No approvals required');
    const approvals = needs.map((a) => requestApproval(inc, a)); pub(inc);
    stage(inc, 'execute', 'running', 'Executing automatic actions');
    const runOne = async (a, by) => { const r = await runAgent(inc, 'GUARDIAN', a.description, () => guardian.execute(a, { incidentId: inc.id, approvedBy: by })); msg(inc, 'GUARDIAN', 'COMMANDER', 'action_result', { id: a.id, type: a.type, ok: !!r?.ok, result: a.result?.detail || r?.error }); pub(inc); if (r?.ok && !inc.containedAt) { inc.containedAt = new Date().toISOString(); inc.timing.containedAt = inc.containedAt; } };
    if (inc.state === 'AWAITING_APPROVAL') { /* automatic actions are allowed to run while waiting */ }
    for (const a of autos) { await runOne(a, 'ai:' + autonomy.getMode()); await pace(0.4); }
    await Promise.all(approvals.map((p) => p.then(async (rec) => { if (rec.decision === 'approved') { const a = inc.containment.find((x) => x.id === rec.actionId); if (inc.state === 'AWAITING_APPROVAL' && !pending.size) setState(inc, 'CONTAINING', 'approvals decided'); await runOne(a, rec.by); } })));
    if (inc.state === 'AWAITING_APPROVAL') setState(inc, 'CONTAINING', 'all approvals decided');
    if (inc.state === 'PLANNING') setState(inc, 'CONTAINING', 'automatic actions executed');
    if (needs.length) stage(inc, 'authorize', 'done', `${inc.approvals.filter((a) => a.decision === 'approved').length} approved · ${inc.approvals.filter((a) => a.decision === 'rejected').length} rejected`);
    const ok = inc.containment.filter((a) => a.status === 'executed').length;
    stage(inc, 'execute', 'done', `${ok}/${inc.containment.length} actions executed${plan.manualOnly.length ? ` · ${plan.manualOnly.length} restricted (manual only)` : ''}`);
  } else { stage(inc, 'authorize', inc.disposition === 'monitor' ? 'skipped' : 'done', 'Nothing to authorize'); stage(inc, 'execute', 'skipped', 'No containment actions'); if (inc.state === 'PLANNING') setState(inc, 'RECOVERING', 'no containment required'); }
  await pace();

  if (inc.disposition === 'monitor') { stage(inc, 'recovery', 'skipped'); stage(inc, 'verify', 'skipped'); inc.verification = { generatedAt: new Date().toISOString(), checks: [{ name: 'Monitor-only disposition: no containment/recovery needed', pass: true, detail: 'Low risk' }], passed: true, failed: 0 }; return finish(inc, 'Monitored — likely benign'); }

  // 10. recovery
  if (inc.state === 'CONTAINING') setState(inc, 'RECOVERING', 'containment complete');
  stage(inc, 'recovery', 'running'); msg(inc, 'COMMANDER', 'RECOVERY', 'task', {});
  inc.recovery = await runAgent(inc, 'RECOVERY', 'Check readiness & build recovery plan', () => recovery.plan(inc, inc.investigation, inc.containment), () => ({ incidentId: inc.id, readiness: [], tasks: [], error: 'RECOVERY unavailable — manual recovery required' }));
  msg(inc, 'RECOVERY', 'COMMANDER', 'recovery_plan', { readiness: inc.recovery.readiness.map((r) => `${r.host}:${r.status}`), tasks: inc.recovery.tasks.length }); pub(inc);
  await recoveryLoop(inc);
  const t = inc.recovery.tasks;
  stage(inc, 'recovery', t.some((x) => x.status === 'failed') ? 'failed' : 'done', `${t.filter((x) => x.status === 'done').length}/${t.length} tasks done`); await pace();

  // 11. verify
  await verifyIncident(inc);
  return finish(inc);
}

async function recoveryLoop(inc) {
  for (;;) {
    const T = inc.recovery.tasks, ready = (t) => t.status === 'pending' && (t.dependsOn || []).every((d) => ['done', 'skipped'].includes(T.find((x) => x.id === d)?.status));
    const auto = T.find((t) => ready(t) && t.owner === 'RECOVERY' && !t.gate);
    if (auto) { await runAgent(inc, 'RECOVERY', auto.title, async () => { try { await recovery.runTask(auto, inc); } catch (e) { auto.status = 'failed'; auto.error = e.message; audit.log('RECOVERY', 'TASK_FAILED', { task: auto.title, error: e.message }, inc.id); } }); pub(inc); await pace(0.5); continue; }
    const human = T.find((t) => ready(t) && t.owner === 'human');
    if (human && settings.autopilot && !cfg.isProd) { await pace(0.8); await completeTask(inc.id, human.id, 'autopilot'); continue; }
    if (!T.some((t) => t.status === 'pending')) return;
    if (!human && !T.some(ready)) { // deps blocked by failed task
      if (T.some((t) => t.status === 'failed')) return;
    }
    await waitSignal(inc);
  }
}
async function verifyIncident(inc) {
  stage(inc, 'verify', 'running'); if (inc.state === 'RECOVERING') setState(inc, 'VERIFYING', 'tasks complete');
  inc.verification = await runAgent(inc, 'RECOVERY', 'Post-recovery verification', () => recovery.verify(inc, inc.postContainmentAlerts), () => ({ generatedAt: new Date().toISOString(), checks: [], passed: false, failed: 1 }));
  msg(inc, 'RECOVERY', 'COMMANDER', 'verification', { passed: inc.verification.passed, failed: inc.verification.failed });
  stage(inc, 'verify', inc.verification.passed ? 'done' : 'failed', inc.verification.passed ? 'All checks passed' : `${inc.verification.failed} check(s) failed`); pub(inc); await pace();
}
async function rerunVerification(incId, by) { const inc = incidents.get(incId); audit.log(by, 'VERIFY_RERUN', {}, incId); await verifyIncident(inc); if (inc.verification.passed) await finish(inc); return inc; }

async function finish(inc, resolution) {
  stage(inc, 'report', 'running');
  inc.lessons = lessons(inc);
  if (!inc.verification?.passed) { inc.status = 'Needs Attention'; inc.statusLocked = false; inc.report = buildReport(inc); stage(inc, 'report', 'done', 'Report generated — verification failed, incident NOT resolved'); audit.log('COMMANDER', 'INCIDENT_NOT_RESOLVED', { failed: inc.verification?.failed }, inc.id); pub(inc); return; }
  inc.timing.resolvedAt = new Date().toISOString(); inc.resolution = resolution || 'Resolved after successful verification';
  setState(inc, 'RESOLVED', inc.resolution); inc.report = buildReport(inc);
  stage(inc, 'report', 'done', 'Final report ready'); msg(inc, 'COMMANDER', 'COMMANDER', 'resolved', { resolution: inc.resolution });
  if (inc.ticket) await ticketing.update(inc.ticket, `Resolved: ${inc.resolution}. Verification passed.`, 'Resolved');
  audit.log('COMMANDER', 'INCIDENT_RESOLVED', { resolution: inc.resolution }, inc.id); pub(inc);
  try { rzMem.record(inc); } catch (e) { audit.log('COMMANDER', 'RZ_HOOK_FAILED', { error: e.message }, inc.id); }
}

// LEARN stage
function lessons(inc) {
  const L = [], rules = new Set(inc.alerts.map((a) => a.rule));
  for (const u of inc.entities.users) if (sim.env.users[u] && !sim.env.users[u].mfa) L.push(`Enforce MFA for ${u} (no MFA was enrolled).`);
  for (const r of inc.recovery.readiness) if (r.status !== 'ready') L.push(`Backup gap on ${r.host}: ${r.note}. Add to verified immutable backup schedule.`);
  if (rules.has('R-CRED-COMPROMISE')) L.push('Add rule: lock account/step-up auth after 5 failures instead of only alerting; add geo-velocity check at login.');
  if (rules.has('R-RANSOMWARE')) L.push('Add rule: alert on first shadow-copy deletion + any single process renaming >20 files in 10s to reduce time-to-isolation.');
  if (rules.has('R-MASS-DOWNLOAD')) L.push('Tune baseline: per-user off-hours download thresholds for HR/Finance restricted shares; enable DLP on egress.');
  if (rules.has('R-PHISH-REPORT') || rules.has('R-PHISH-CLICK')) L.push('Block newly-registered domains (<30 days) at proxy/DNS; run phishing-report triage automation for all reports.');
  if (rules.has('R-CLOUD-ADMIN') || rules.has('R-CLOUD-BLIND')) L.push('Add SCP preventing StopLogging/DeleteTrail and AdministratorAccess attachment outside change pipeline.');
  if (inc.degraded) L.push('One or more agents degraded during this incident — review AGENT_FAILED audit entries.');
  if (inc.containment.some((a) => a.status === 'denied')) L.push('Review denied containment actions: residual risk was accepted by a human reviewer.');
  if (!L.length) L.push('No detection gaps identified; keep existing rules.');
  return L;
}

function buildReport(inc) {
  const i = inc.investigation, fmt = (t) => new Date(t).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  const ttc = inc.timing.containedAt ? Math.round((new Date(inc.timing.containedAt) - new Date(inc.timing.detectedAt)) / 1000) + 's' : 'n/a';
  const L = [];
  L.push(`# Incident Report ${inc.id} — ${inc.title}`, '', `**Generated:** ${fmt(new Date())} · **Priority:** ${inc.priority} · **Severity:** ${inc.severity} · **Risk:** ${inc.riskScore}/100 · **Status:** ${inc.status}`, `**Data origin:** ${inc.origin === 'ingested' ? 'REAL ingested data' : 'SIMULATED / synthetic events'}`, '', '## 1. Executive summary', i.summary, `Detection-to-containment time: **${ttc}**. Investigation confidence: **${i.confidence}** (${i.confidenceReason || 'n/a'}).`);
  if (i.aiNarrative) L.push('', `> AI briefing (${i.aiNarrative.model}; prose only, not evidence): ${i.aiNarrative.text}`);
  L.push('', '## 2. Timeline', ...i.timeline.map((t) => `- ${fmt(t.ts)} · **${t.phase}** · ${t.summary}${t.suspicious ? ' ⚠' : ''}`));
  L.push('', '## 3. Evidence', `Preserved ${inc.evidence.count} event(s); SHA-256 \`${inc.evidence.sha256}\`.`, '### Confirmed findings', ...inc.alerts.map((a) => `- [${a.rule}] ${a.evidenceSummary} (risk ${a.riskScore}, ${a.evidence.length} event(s))`), '### Hypotheses (NOT confirmed)', ...i.hypotheses.map((h) => `- ${h.statement} — confidence ${h.confidence}. To confirm: ${h.toConfirm}`));
  L.push('', '## 4. MITRE ATT&CK', ...i.techniques.map((t) => `- ${t.id} ${t.name}: **${t.status}** — ${t.basis}`));
  L.push('', '## 5. Threat intelligence', inc.intel.summary, ...inc.intel.indicators.map((x) => `- ${x.type} \`${x.indicator}\`: **${x.verdict}** (${x.source}) ${x.detail}`));
  L.push('', '## 6. Impact assessment', ...i.affectedAssets.map((a) => `- ${a.type} ${a.id}: ${a.status}`));
  L.push('', '## 7. Response', ...inc.containment.map((a) => `- [${a.tier}] ${a.description}: **${a.status}**${a.result ? ' — ' + a.result.detail : ''}${a.approvedBy ? ' (by ' + a.approvedBy + ')' : ''}`), ...(inc.plan?.manualOnly || []).map((m) => `- [RESTRICTED – manual only] ${m.description}: ${m.why}`));
  L.push('', '## 8. Recovery', ...inc.recovery.readiness.map((r) => `- Readiness ${r.host}: **${r.status}** — ${r.note}`), ...inc.recovery.tasks.map((t) => `- [${t.status}] ${t.title} (${t.owner})`));
  L.push('', '## 9. Verification', ...(inc.verification?.checks || []).map((c) => `- ${c.pass ? 'PASS' : 'FAIL'}: ${c.name} — ${c.detail}`));
  L.push('', '## 10. Recommended next steps / lessons learned', ...inc.lessons.map((l) => `- ${l}`), '', '## 11. Applicable playbooks (knowledge base)', ...inc.playbooks.map((p) => `- ${p.id} ${p.title}`));
  L.push('', '## 12. Integrations', `Notifications: ${inc.notifications.map((n) => `${n.channel}=${n.status}`).join(', ') || 'none'} · Ticket: ${inc.ticket ? `${inc.ticket.id} (${inc.ticket.system}${inc.ticket.confirmed ? ', provider-confirmed' : ', SIMULATED — not an external ticket'})` : 'none'}`);
  return L.join('\n');
}

// ---------- Unblock / self-recovery ----------
const targetKey = (t) => t.ip ? ['ip', t.ip] : t.user ? ['user', t.user] : t.host ? ['host', t.host] : t.resource ? ['resource', t.resource] : null;
// ---------- Manual actions: a person tells the AI to block/disable something (chat or API). The AI executes it. ----------
let manual = [];
const MANUAL_TYPES = ['block_ip', 'disable_account', 'revoke_sessions', 'force_password_reset', 'isolate_host', 'restrict_resource'];
const saveManual = () => { try { require('../core/db').kvSet('manual_actions', manual.slice(-300)); } catch { /* best effort */ } };
function loadManual() { try { const m = require('../core/db').kvGet('manual_actions', null); if (Array.isArray(m)) manual = m; } catch { /* first boot */ } }
async function manualAction(type, target, by, reason = '') {
  if (!MANUAL_TYPES.includes(type)) throw new Error('I can do these on request: ' + MANUAL_TYPES.join(', '));
  const prot = autonomy.isProtected(target); if (prot) throw new Error(`that target is protected (${prot.reason}). An admin must remove the protection first.`);
  const a = guardian.mk(type, target, reason || `Requested by ${by}`); a.manual = true; a.requestedBy = by;
  if (guardian.classify(type, target).tier === 'restricted') throw new Error('that action is never executed by PHOENIX');
  const r = await guardian.execute(a, { incidentId: null, approvedBy: by });
  a.simulated = a.result?.provider === 'simulated-enterprise'; a.incidentId = 'MANUAL'; manual.push(a); saveManual();
  audit.log(by, 'MANUAL_ACTION', { type, target, status: a.status, reason }, null);
  return { action: a, ...r, status: a.status, detail: a.result?.detail };
}
function containments() {
  const out = [];
  for (const a of manual) if (a.status === 'executed' && guardian.CATALOG[a.type]?.undo) out.push({ id: a.id, incidentId: 'MANUAL', incidentTitle: 'Manual action by ' + a.requestedBy, type: a.type, target: a.target, description: a.description, by: a.requestedBy, aiAuto: false, mode: null, rationale: a.reason, at: a.executedAt, expiresAt: null, simulated: !!a.simulated, dryRun: false });
  for (const inc of incidents.values()) for (const a of inc.containment || []) {
    if (a.status !== 'executed' || !guardian.CATALOG[a.type]?.undo) continue;
    out.push({ id: a.id, incidentId: inc.id, incidentTitle: inc.title, type: a.type, target: a.target, description: a.description, by: a.approvedBy, aiAuto: !!a.aiAuto, mode: a.autonomyMode || null, rationale: a.rationale || a.policyReason, at: a.executedAt, expiresAt: a.expiresAt || null, simulated: a.result?.provider === 'simulated-enterprise', dryRun: false });
  }
  return out.sort((x, y) => String(y.at).localeCompare(String(x.at)));
}
// A human lifts a block. The AI will not re-apply it on its own for 24 h (or ever, with trust=true).
async function undoAction(actionId, by, { trust = false, reason = '' } = {}) {
  const m = manual.find((x) => x.id === actionId);
  if (m) { if (m.status !== 'executed') throw new Error('action is not active (status: ' + m.status + ')'); const r = await guardian.rollback(m, null, by); if (!r.ok) throw new Error('could not undo this action'); saveManual(); const k = targetKey(m.target); if (k) autonomy.protect({ kind: k[0], value: k[1], reason: (reason || 'Unblocked by ' + by).slice(0, 200), hours: trust ? null : 24 }, by); audit.log(by, 'ACTION_UNBLOCKED', { id: m.id, type: m.type, target: m.target, trusted: !!trust }, null); return m; }
  for (const inc of incidents.values()) {
    const a = (inc.containment || []).find((x) => x.id === actionId); if (!a) continue;
    if (a.status !== 'executed') throw new Error('action is not active (status: ' + a.status + ')');
    const r = await guardian.rollback(a, inc.id, by);
    if (!r.ok) throw new Error('could not undo this action' + (cfg.connectorDryRun && a.simulated === false ? ' (connectors are in dry-run)' : ''));
    a.unblockedBy = by; a.unblockedAt = new Date().toISOString();
    const k = targetKey(a.target);
    if (k) autonomy.protect({ kind: k[0], value: k[1], reason: (reason || 'Unblocked by ' + by).slice(0, 200), hours: trust ? null : 24 }, by);
    audit.log(by, 'ACTION_UNBLOCKED', { id: a.id, type: a.type, target: a.target, trusted: !!trust, reason }, inc.id); pub(inc); return a;
  }
  throw new Error('action not found');
}
// Self-recovery: the AI lifts its OWN expired containment, but only the kinds the current mode allows, and only if the entity has been quiet.
async function sweepExpired() {
  const now = Date.now(); let lifted = 0;
  for (const inc of incidents.values()) for (const a of inc.containment || []) {
    if (!a.aiAuto || a.status !== 'executed' || !a.expiresAt || Date.parse(a.expiresAt) > now || !autonomy.canAutoLift(a.type)) continue;
    const quiet = !(inc.alerts || []).some((x) => Date.parse(x.ts) > Date.parse(a.executedAt) + 60e3);
    if (!quiet) { a.expiresAt = new Date(now + 24 * 3600e3).toISOString(); audit.log('GUARDIAN', 'AI_LIFT_DEFERRED', { id: a.id, why: 'new related alerts since containment' }, inc.id); continue; }
    try { const r = await guardian.rollback(a, inc.id, 'ai:self-recovery'); if (r.ok) { lifted++; a.unblockedBy = 'ai:self-recovery'; a.unblockedAt = new Date().toISOString(); audit.log('GUARDIAN', 'AI_SELF_RECOVERY', { id: a.id, type: a.type, target: a.target }, inc.id); pub(inc); } } catch (e) { audit.log('GUARDIAN', 'AI_LIFT_FAILED', { id: a.id, error: e.message }, inc.id); }
  }
  return lifted;
}
function setAutopilot(v) { settings.autopilot = !!v; if (v) { for (const p of pendingFor()) decide(p.action.id, true, 'autopilot', 'Autopilot enabled').catch(() => {}); for (const inc of incidents.values()) signal(inc); } audit.log('COMMANDER', 'AUTOPILOT', { enabled: !!v }); }
// ---------- Analyst operations ----------
function addNote(id, by, text) { const inc = incidents.get(id); inc.notes.push({ ts: new Date().toISOString(), by, text }); audit.log(by, 'NOTE_ADDED', { text }, id); pub(inc); return inc; }
function assign(id, by, analyst) { const inc = incidents.get(id); inc.analyst = analyst; audit.log(by, 'ANALYST_ASSIGNED', { analyst }, id); pub(inc); return inc; }
function setStatus(id, by, status) { const inc = incidents.get(id); if (!['Open', 'In Progress', 'Escalated', 'False Positive', 'Closed', 'Resolved'].includes(status)) throw new Error('invalid status'); inc.status = status; inc.statusLocked = true; if (status === 'Closed' && inc.state === 'RESOLVED') setState(inc, 'CLOSED', 'analyst closed'); audit.log(by, 'STATUS_CHANGED', { status }, id); pub(inc); return inc; }

function metrics() {
  const L = [...incidents.values()], open = L.filter((i) => !['RESOLVED', 'CLOSED'].includes(i.state));
  const ttc = L.filter((i) => i.timing.containedAt).map((i) => (new Date(i.timing.containedAt) - new Date(i.timing.detectedAt)) / 1000);
  const comp = new Set(open.flatMap((i) => [...i.entities.users.filter((u) => ['suspended'].includes(sim.env.users[u]?.status) || i.alerts.some((a) => ['R-CRED-COMPROMISE', 'R-TOKEN-REUSE'].includes(a.rule))), ...i.entities.hosts.filter((h) => i.alerts.some((a) => ['R-RANSOMWARE', 'R-MACRO', 'R-BEACON'].includes(a.rule)))]));
  const w = { critical: 42, high: 24, medium: 10, low: 3 };
  return { activeIncidents: open.length, criticalThreats: open.filter((i) => i.severity === 'critical').length, totalIncidents: L.length, resolved: L.filter((i) => i.state === 'RESOLVED').length, compromisedAssets: comp.size, avgContainSec: ttc.length ? Math.round(ttc.reduce((a, b) => a + b, 0) / ttc.length) : null, riskScore: clamp(Math.round(open.reduce((s, i) => s + (w[i.severity] || 0), 8)), 0, 100), pendingApprovals: pending.size };
}
// Restore incidents after a restart. Anything that was mid-workflow is NOT silently resumed: it is flagged for a human.
function restore(list) {
  let restored = 0, interrupted = 0;
  for (const inc of list) {
    incidents.set(inc.id, inc); restored++; seq = Math.max(seq, +inc.id.replace('INC-', '') || seq);
    if (!['RESOLVED', 'CLOSED', 'MONITORING'].includes(inc.state) && inc.status !== 'Needs Attention') {
      interrupted++; inc.interrupted = true; inc.status = 'Needs Attention'; inc.statusLocked = true;
      for (const a of inc.containment) if (['pending_approval', 'planned', 'approved'].includes(a.status)) { a.status = 'blocked'; a.error = 'Server restarted before execution; re-evaluate manually'; }
      inc.notes.push({ ts: new Date().toISOString(), by: 'SYSTEM', text: `Server restarted while incident was ${inc.state}. The workflow was not resumed automatically; pending actions were cancelled. Review and re-run manually.` });
      audit.log('COMMANDER', 'INCIDENT_INTERRUPTED_BY_RESTART', { state: inc.state }, inc.id);
    }
  }
  return { restored, interrupted };
}
// Analyst-triggered resume of an incident that was interrupted by a restart (never automatic).
async function resume(id, by) {
  const inc = incidents.get(id); if (!inc || !inc.interrupted) throw new Error('incident is not interrupted');
  audit.log(by, 'INCIDENT_RESUMED', { from: inc.state }, id);
  inc.stateHistory.push({ from: inc.state, to: 'TRIAGED', ts: new Date().toISOString(), why: 'resumed by ' + by }); inc.state = 'TRIAGED';
  inc.interrupted = false; inc.status = 'In Progress'; inc.statusLocked = false;
  for (const w of inc.workflow.slice(2)) { w.status = 'pending'; delete w.note; } inc.containment = []; inc.recovery = { readiness: [], tasks: [] }; inc.verification = null; inc.degraded = false; pub(inc);
  runPipeline(inc).catch((e) => { audit.log('COMMANDER', 'PIPELINE_CRASH_CONTAINED', { error: e.message }, id); inc.degraded = true; pub(inc); });
  return inc;
}
function reset() { manual = []; incidents.clear(); pending.clear(); waiters.clear(); messages.length = 0; executions.length = 0; seq = 1000; for (const a of Object.values(agentStats)) Object.assign(a, { runs: 0, failures: 0, state: 'idle', last: null }); sentinel.reset(); }

// Wire detection: every event goes through SENTINEL, alerts go to COMMANDER.
function attach() { bus.on('event', (e) => { try { for (const a of sentinel.process(e)) receiveAlert(a); } catch (err) { agentStats.SENTINEL.failures++; audit.log('SENTINEL', 'AGENT_FAILED', { error: err.message }, null); } }); }
module.exports = { manualList: () => manual, manualAction, loadManual, MANUAL_TYPES, checkTask, sweepChecks, skipTask, containments, undoAction, sweepExpired, attach, restore, resume, setAutopilot, settings, incidents, messages, agentStats, executions, decide, pendingFor, completeTask, rerunVerification, addNote, assign, setStatus, metrics, reset, STAGES, receiveAlert, buildReport };
