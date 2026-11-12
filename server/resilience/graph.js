'use strict';
// APPLICATION DEPENDENCY GRAPH. Edge "A -> B" means "A depends on B" (A uses / is built from / holds a credential for B).
// Compromise or failure of B therefore affects everything that can reach B going "up" the dependency edges.
// Every node/edge carries a confidence: verified (read from a provider API / matched on a real value),
// declared (entered by an admin) or inferred (a naming heuristic). Env VALUES are never stored.
const db = require('../core/db');
const audit = require('../core/audit');

const CONF = ['verified', 'declared', 'inferred']; const rank = (c) => CONF.indexOf(c);
const now = () => new Date().toISOString();
const nrow = (r) => r && ({ id: r.id, type: r.type, provider: r.provider, name: r.name, meta: JSON.parse(r.meta || '{}'), source: r.source, confidence: r.confidence, updatedAt: r.updated_at });
const erow = (r) => r && ({ id: r.id, src: r.src, dst: r.dst, kind: r.kind, confidence: r.confidence, evidence: r.evidence, source: r.source });
const eid = (s, d, k) => `${s}>${k}>${d}`;

function upsertNode({ id, type, provider = null, name, meta = {}, source = 'declared', confidence = 'declared' }) {
  if (!id || !type || !name) throw new Error('id, type and name required');
  const old = db.get().prepare('select confidence from rz_nodes where id=?').get(id);
  const conf = old && rank(old.confidence) < rank(confidence) ? old.confidence : confidence; // never downgrade
  db.get().prepare('insert into rz_nodes(id,type,provider,name,meta,source,confidence,updated_at) values(?,?,?,?,?,?,?,?) on conflict(id) do update set type=excluded.type, provider=excluded.provider, name=excluded.name, meta=excluded.meta, source=excluded.source, confidence=?, updated_at=excluded.updated_at').run(id, type, provider, String(name).slice(0, 120), JSON.stringify(meta), source, conf, now(), conf);
  return id;
}
function upsertEdge({ src, dst, kind, confidence = 'declared', evidence = '', source = 'declared' }) {
  if (!src || !dst || !kind) throw new Error('src, dst and kind required');
  const id = eid(src, dst, kind); const old = db.get().prepare('select confidence from rz_edges where id=?').get(id);
  const conf = old && rank(old.confidence) < rank(confidence) ? old.confidence : confidence;
  db.get().prepare('insert into rz_edges(id,src,dst,kind,confidence,evidence,source) values(?,?,?,?,?,?,?) on conflict(id) do update set confidence=?, evidence=excluded.evidence, source=excluded.source').run(id, src, dst, kind, conf, String(evidence).slice(0, 200), source, conf);
  return id;
}
const nodes = () => db.get().prepare('select * from rz_nodes order by type,name').all().map(nrow);
const edges = () => db.get().prepare('select * from rz_edges').all().map(erow);
const node = (id) => nrow(db.get().prepare('select * from rz_nodes where id=?').get(id));
function removeBySource(source) { db.get().prepare('delete from rz_edges where source=?').run(source); db.get().prepare('delete from rz_nodes where source=?').run(source); }
function removeNode(id, by) { db.get().prepare('delete from rz_edges where src=? or dst=?').run(id, id); const r = db.get().prepare('delete from rz_nodes where id=?').run(id); audit.log(by, 'RZ_NODE_REMOVED', { id }); return r.changes > 0; }
function addDeclared({ node: n, edge: e }, by) {
  if (n) upsertNode({ ...n, source: 'declared', confidence: 'declared' });
  if (e) { for (const x of [e.src, e.dst]) if (!node(x)) throw new Error('unknown node ' + x); upsertEdge({ ...e, source: 'declared', confidence: 'declared' }); }
  audit.log(by, 'RZ_GRAPH_EDIT', { node: n?.id, edge: e && eid(e.src, e.dst, e.kind) }); return { ok: true };
}

// Everything that (transitively) depends on `id`. Returns [{ node, depth, path:[ids from origin], confidence }] (BFS, shortest path).
function dependents(id, maxDepth = 6) {
  const E = edges(), byDst = new Map(); for (const e of E) { if (!byDst.has(e.dst)) byDst.set(e.dst, []); byDst.get(e.dst).push(e); }
  // best path per node: strongest confidence first (a verified route beats a shorter inferred one), then shortest
  const best = new Map([[id, { depth: 0, path: [id], conf: 'verified' }]]), q = [id];
  while (q.length) {
    const cur = q.shift(), c = best.get(cur); if (c.depth >= maxDepth) continue;
    for (const e of byDst.get(cur) || []) {
      if (e.src === id) continue;
      const conf = rank(c.conf) >= rank(e.confidence) ? c.conf : e.confidence, v = { depth: c.depth + 1, path: [...c.path, e.src], conf, via: e.kind }, o = best.get(e.src);
      if (!o || rank(conf) < rank(o.conf) || (rank(conf) === rank(o.conf) && v.depth < o.depth)) { best.set(e.src, v); q.push(e.src); }
    }
  }
  const out = []; for (const [nid, v] of best) { if (nid === id) continue; const n = node(nid); if (n) out.push({ node: n, depth: v.depth, path: v.path, confidence: v.conf, via: v.via }); }
  out.sort((x, y) => x.depth - y.depth);
  return out;
}
// What `id` depends on (what a compromised secret/service could reach).
function dependencies(id, maxDepth = 4) {
  const E = edges(), bySrc = new Map(); for (const e of E) { if (!bySrc.has(e.src)) bySrc.set(e.src, []); bySrc.get(e.src).push(e); }
  const seen = new Set([id]), q = [[id, 0]], out = [];
  while (q.length) { const [cur, d] = q.shift(); if (d >= maxDepth) continue; for (const e of bySrc.get(cur) || []) { if (seen.has(e.dst)) continue; seen.add(e.dst); q.push([e.dst, d + 1]); const n = node(e.dst); if (n) out.push({ node: n, depth: d + 1, confidence: e.confidence, via: e.kind }); } }
  return out;
}
function summary() {
  const N = nodes(), E = edges(), by = (a, f) => a.reduce((m, x) => (m[f(x)] = (m[f(x)] || 0) + 1, m), {});
  return { nodes: N.length, edges: E.length, byType: by(N, (n) => n.type), byProvider: by(N, (n) => n.provider || 'other'), byConfidence: by(E, (e) => e.confidence) };
}
function find(q) { q = String(q || '').toLowerCase().trim(); if (!q) return []; const N = nodes(); const ex = N.filter((n) => n.id.toLowerCase() === q || n.name.toLowerCase() === q); return ex.length ? ex : N.filter((n) => n.id.toLowerCase().includes(q) || n.name.toLowerCase().includes(q)); }
module.exports = { upsertNode, upsertEdge, nodes, edges, node, removeBySource, removeNode, addDeclared, dependents, dependencies, summary, find, CONF };
