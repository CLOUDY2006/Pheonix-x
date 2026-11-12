'use strict';
// SECURITY EVIDENCE & INCIDENT MEMORY. Every resolved/handled incident is stored as a signed-by-hash record (events, findings, timeline, actions,
// approvals, recovery result, verification, evidence hash). New incidents are compared by signature (Jaccard similarity) and the earlier
// incident's successful procedure is suggested. The record keeps references and hashes, not raw logs.
const crypto = require('crypto'); const db = require('../core/db'); const audit = require('../core/audit');

const sigOf = (inc) => { const s = new Set(); for (const a of inc.alerts || []) { if (a.rule) s.add('rule:' + a.rule); if (a.category) s.add('cat:' + a.category); for (const m of a.mitre || []) s.add('mitre:' + (m.id || m)); } for (const k of ['users', 'hosts', 'ips', 'domains', 'resources']) if ((inc.entities?.[k] || []).length) s.add('ent:' + k); return [...s]; };
const jac = (a, b) => { const A = new Set(a), B = new Set(b); if (!A.size || !B.size) return 0; let i = 0; for (const x of A) if (B.has(x)) i++; return i / (A.size + B.size - i); };
function record(inc) {
  const rec = { incidentId: inc.id, title: inc.title, severity: inc.severity, state: inc.state, at: new Date().toISOString(), openedAt: inc.timing?.createdAt || inc.createdAt || null, resolvedAt: inc.timing?.resolvedAt || null,
    signature: sigOf(inc), findings: (inc.alerts || []).map((a) => ({ rule: a.rule, summary: a.evidenceSummary, risk: a.riskScore })), timeline: (inc.investigation?.timeline || []).slice(0, 40).map((t) => ({ ts: t.ts, summary: t.summary })),
    actions: (inc.containment || []).map((a) => ({ type: a.type, target: a.target, status: a.status, approvedBy: a.approvedBy || null, tier: a.tier })), recovery: (inc.recovery?.tasks || []).map((t) => ({ title: t.title, status: t.status, kind: t.kind })),
    verification: inc.verification ? { passed: !!inc.verification.passed, failed: inc.verification.failed } : null, blast: inc.blast ? { affected: inc.blast.counts?.total, deployments: inc.blast.connectedDeployments } : null,
    evidence: { sha256: inc.evidence?.sha256 || null, count: inc.evidence?.count || 0 }, lessons: inc.lessons || [] };
  rec.sha256 = crypto.createHash('sha256').update(JSON.stringify(rec)).digest('hex');
  db.get().prepare('insert into rz_memory(id,incident,sig,record,at) values(?,?,?,?,?) on conflict(id) do update set sig=excluded.sig, record=excluded.record, at=excluded.at').run('mem-' + inc.id, inc.id, JSON.stringify(rec.signature), JSON.stringify(rec), rec.at);
  audit.log('COMMANDER', 'RZ_MEMORY_RECORDED', { incident: inc.id, sha256: rec.sha256.slice(0, 16) }, inc.id); return rec;
}
const all = () => db.get().prepare('select record from rz_memory order by at desc').all().map((r) => JSON.parse(r.record));
const get = (incidentId) => { const r = db.get().prepare('select record from rz_memory where incident=?').get(incidentId); return r ? JSON.parse(r.record) : null; };
function similar(inc, limit = 3) {
  const sig = Array.isArray(inc) ? inc : sigOf(inc), id = Array.isArray(inc) ? null : inc.id;
  return all().filter((m) => m.incidentId !== id).map((m) => ({ m, score: jac(sig, m.signature) })).filter((x) => x.score >= 0.34).sort((a, b) => b.score - a.score).slice(0, limit).map(({ m, score }) => {
    const worked = m.actions.filter((a) => ['executed', 'completed', 'success', 'done'].includes(a.status) || /exec|done|confirm/i.test(a.status || '')), tasks = m.recovery.filter((t) => t.status === 'done');
    return { incidentId: m.incidentId, title: m.title, similarity: Math.round(score * 100), at: m.at, verified: !!m.verification?.passed, procedure: [...worked.map((a) => `${a.type} → ${a.target}`), ...tasks.map((t) => t.title)].slice(0, 8), lessons: (m.lessons || []).slice(0, 3), evidenceSha256: m.evidence.sha256, sharedSignals: m.signature.filter((s) => sig.includes(s)).slice(0, 6) };
  });
}
// Verifiable bundle for an incident: re-hash to prove the record was not altered.
function bundle(incidentId) { const m = get(incidentId); if (!m) return null; const { sha256, ...rest } = m; return { record: m, integrity: { stored: sha256, recomputed: crypto.createHash('sha256').update(JSON.stringify(rest)).digest('hex') } }; }
module.exports = { record, similar, get, all, bundle, sigOf };
