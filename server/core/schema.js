'use strict';
// Minimal structural validator so every agent-to-agent message is checked JSON, never free text.
// spec: { field: 'string' | 'number' | 'boolean' | 'array' | 'object' | ['enum', 'values'] , '?field': optional }
function validate(spec, obj, name = 'message') {
  const errors = [];
  if (!obj || typeof obj !== 'object') return { ok: false, errors: [`${name} is not an object`] };
  for (const [k, t] of Object.entries(spec)) {
    const optional = k.startsWith('?');
    const key = optional ? k.slice(1) : k;
    const v = obj[key];
    if (v === undefined || v === null) { if (!optional) errors.push(`${name}.${key} missing`); continue; }
    if (Array.isArray(t)) { if (!t.includes(v)) errors.push(`${name}.${key} must be one of ${t.join('|')}`); }
    else if (t === 'array') { if (!Array.isArray(v)) errors.push(`${name}.${key} must be array`); }
    else if (t === 'object') { if (typeof v !== 'object' || Array.isArray(v)) errors.push(`${name}.${key} must be object`); }
    else if (typeof v !== t) errors.push(`${name}.${key} must be ${t}`);
  }
  return { ok: errors.length === 0, errors };
}
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const SPECS = {
  alert: { id: 'string', agent: 'string', category: 'string', rule: 'string', riskScore: 'number', severity: SEVERITIES, evidence: 'array', affected: 'object', recommendedAction: 'string', ts: 'string' },
  investigation: { incidentId: 'string', summary: 'string', timeline: 'array', evidence: 'array', affectedAssets: 'array', techniques: 'array', confidence: ['low', 'medium', 'high'], recommendedResponse: 'array', graph: 'object', hypotheses: 'array' },
  intel: { indicators: 'array', summary: 'string' },
  plan: { incidentId: 'string', actions: 'array', manualOnly: 'array' },
  recovery: { incidentId: 'string', readiness: 'array', tasks: 'array' },
};
module.exports = { validate, SPECS, SEVERITIES };
