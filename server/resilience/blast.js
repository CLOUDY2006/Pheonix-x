'use strict';
// BLAST RADIUS INTELLIGENCE: given a compromised node (secret / repo / service / provider), what is connected and what must change.
const graph = require('./graph');
const IMPACT = {
  deployment: 'Holds or uses the affected credential: update the replacement value, then redeploy so the running app picks it up.',
  secret: 'Environment variable that may carry the affected credential: replace its value.',
  database: 'Access keys for this database must be rotated; check data integrity and backups.',
  repo: 'Source of one or more deployments: rotate access tokens and review recent commits and workflows.',
  external: 'Third-party service reachable with the affected credential: rotate there too.',
};
function compute(originIds) {
  const ids = [...new Set([].concat(originIds || []))].filter((i) => graph.node(i)); const map = new Map();
  const put = (n, depth, conf, via, why, path) => { const cur = map.get(n.id); if (!cur || depth < cur.depth) map.set(n.id, { id: n.id, name: n.name, type: n.type, provider: n.provider, depth, confidence: conf, via, reason: why, path: path || [], impact: IMPACT[n.type] || '' }); };
  for (const id of ids) {
    const o = graph.node(id);
    for (const d of graph.dependents(id)) put(d.node, d.depth, d.confidence, d.via, `depends on ${o.name}`, d.path);
    if (o.type === 'secret') for (const d of graph.dependencies(id, 2)) put(d.node, d.depth, d.confidence, d.via, `reachable with ${o.name}`, [id, d.node.id]);
    // a compromised repo/deployment can read the secrets its deployments hold
    for (const a of [o, ...graph.dependents(id).map((x) => x.node)].filter((n) => n.type === 'deployment')) for (const d of graph.dependencies(a.id, 1)) if (d.node.type === 'secret') put(d.node, 1, d.confidence === 'verified' ? 'inferred' : d.confidence, 'potentially_exposed', `held by ${a.name}, which a compromise of ${o.name} could read`, [id, a.id, d.node.id]);
  }
  const affected = [...map.values()].filter((a) => !ids.includes(a.id)).sort((a, b) => a.depth - b.depth || a.name.localeCompare(b.name));
  const by = (t) => affected.filter((a) => a.type === t);
  const redeploy = by('deployment');
  return {
    origins: ids.map((i) => { const n = graph.node(i); return { id: n.id, name: n.name, type: n.type, provider: n.provider }; }),
    affected, counts: { total: affected.length, verified: affected.filter((a) => a.confidence === 'verified').length, inferred: affected.filter((a) => a.confidence !== 'verified').length },
    connectedDeployments: redeploy.map((a) => a.name), repos: by('repo').map((a) => a.name), exposedSecrets: by('secret').map((a) => a.name), downstream: [...by('database'), ...by('external')].map((a) => a.name),
    needsRedeploy: redeploy.map((a) => ({ id: a.id, name: a.name, provider: a.provider })),
    caveat: affected.some((a) => a.confidence !== 'verified') ? 'Some links are inferred from variable names, not confirmed by an API. Treat them as likely, and confirm in the provider dashboard.' : null,
  };
}
// Which graph nodes does an incident touch? Matches node/service/repo names and variable names against the incident text. Marked inferred.
function forIncident(inc) {
  const text = [inc.title, inc.summary, ...(inc.alerts || []).flatMap((a) => [a.evidenceSummary, a.title, a.entity]), ...Object.values(inc.entities || {}).flat().map(String)].filter(Boolean).join(' \n ').toLowerCase();
  if (!text.trim()) return null;
  const hits = graph.nodes().filter((n) => n.type !== 'external' && ((n.name.length >= 3 && text.includes(n.name.toLowerCase().split(':').pop())) || (n.type === 'secret' && n.meta?.variable && text.includes(n.meta.variable.toLowerCase()))));
  const roots = hits.filter((n) => n.type !== 'secret' || true).map((n) => n.id); if (!roots.length) return null;
  const b = compute(roots); b.basis = 'matched by name in incident evidence (inferred)'; return b;
}
module.exports = { compute, forIncident };
