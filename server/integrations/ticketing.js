'use strict';
// Ticketing: Jira Cloud REST if JIRA_* set, otherwise a fully working local simulator.
// A ticket is "confirmed" only when Jira returns an issue key.
const sim = require('../sim/enterprise');
const audit = require('../core/audit');
const bus = require('../core/bus');
const E = process.env;
const jiraOn = () => !!(E.JIRA_BASE_URL && E.JIRA_EMAIL && E.JIRA_API_TOKEN && E.JIRA_PROJECT);
const roster = ['dave.okafor (IT Sec on-call)', 'soc-tier2@corp.example', 'ir-lead@corp.example'];
let n = 100, rr = 0;
const PRI = { P1: 'Highest', P2: 'High', P3: 'Medium', P4: 'Low' };
const auth = () => ({ Authorization: 'Basic ' + Buffer.from(`${E.JIRA_EMAIL}:${E.JIRA_API_TOKEN}`).toString('base64'), 'content-type': 'application/json' });
const adf = (t) => ({ type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: t.slice(0, 30000) }] }] });

async function create(incident) {
  const t = { id: 'PHX-' + ++n, system: 'local-simulator', confirmed: false, title: `[${incident.priority}] ${incident.title}`, priority: incident.priority, owner: roster[rr++ % roster.length], status: 'Open', createdAt: new Date().toISOString(), comments: [], incidentId: incident.id };
  if (jiraOn()) {
    try {
      const r = await fetch(`${E.JIRA_BASE_URL}/rest/api/3/issue`, { method: 'POST', headers: auth(), signal: AbortSignal.timeout(10000), body: JSON.stringify({ fields: { project: { key: E.JIRA_PROJECT }, summary: t.title, issuetype: { name: E.JIRA_ISSUE_TYPE || 'Task' }, description: adf(incident.investigation?.summary || incident.title), ...(E.JIRA_ASSIGNEE_ID ? { assignee: { accountId: E.JIRA_ASSIGNEE_ID } } : {}) } }) });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.key) Object.assign(t, { id: j.key, system: 'jira', confirmed: true, url: `${E.JIRA_BASE_URL}/browse/${j.key}` });
      else t.error = 'Jira HTTP ' + r.status + ' — fell back to local simulator';
    } catch (e) { t.error = e.message + ' — fell back to local simulator'; }
  }
  sim.env.tickets.push(t); bus.emit('ticket', t);
  audit.log('TICKETING', t.confirmed ? 'TICKET_CREATED_CONFIRMED' : 'TICKET_CREATED_SIMULATED', { id: t.id, system: t.system, priority: t.priority, owner: t.owner, error: t.error }, incident.id);
  return t;
}
async function update(t, comment, status) {
  if (!t) return;
  t.comments.push({ ts: new Date().toISOString(), text: comment }); if (status) t.status = status; bus.emit('ticket', t);
  if (t.system === 'jira' && t.confirmed) { try { const r = await fetch(`${E.JIRA_BASE_URL}/rest/api/3/issue/${t.id}/comment`, { method: 'POST', headers: auth(), body: JSON.stringify({ body: adf(comment) }), signal: AbortSignal.timeout(10000) }); t.lastSyncOk = r.ok; } catch { t.lastSyncOk = false; } }
}
const status = () => (jiraOn() ? 'configured' : 'simulator');
module.exports = { create, update, status, PRI };
