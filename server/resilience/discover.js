'use strict';
// DISCOVERY: reads your connected providers (read-only API calls with the stored tokens) and builds the dependency graph.
// Stores NAMES only: service names, env variable NAMES and the host part of URL-valued variables. Values are never persisted.
const col = require('../collectors');
const graph = require('./graph');
const audit = require('../core/audit');

const H = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return null; } };
const sid = (...p) => p.join(':').toLowerCase();
// Variable-name heuristics -> what the credential most likely belongs to (always marked "inferred").
const PATTERNS = [
  [/^(NEXT_PUBLIC_)?SUPABASE/i, 'supabase'], [/^(DATABASE_URL|POSTGRES|PG(HOST|URL)|DB_URL|MONGO|MYSQL)/i, 'database'], [/^REDIS|^UPSTASH/i, 'redis'],
  [/^STRIPE_/i, 'stripe'], [/^(OPENAI|ANTHROPIC)_/i, 'llm-api'], [/^(SENDGRID|RESEND|POSTMARK|MAILGUN)_/i, 'email-provider'], [/^(AWS_|S3_)/i, 'aws'], [/^(JWT|SESSION|AUTH|NEXTAUTH)_?.*(SECRET|KEY)/i, 'auth-secret'],
];
const SECRETISH = /(KEY|SECRET|TOKEN|PASSWORD|PASS|DSN|URL|CREDENTIAL)/i;

async function vercel(c) {
  const b = col.BASE.vercel(), q = c.config.teamId ? `teamId=${encodeURIComponent(c.config.teamId)}` : '';
  const d = await col.http(`${b}/v9/projects?${q}&limit=100`, { token: c.token }); const out = [];
  for (const p of d.projects || []) {
    if (c.config.projectId && p.id !== c.config.projectId && p.name !== c.config.projectId) continue;
    let vars = []; try { const e = await col.http(`${b}/v9/projects/${p.id}/env?${q}`, { token: c.token }); vars = (e.envs || []).map((v) => ({ key: v.key, value: v.type === 'plain' ? v.value : undefined })); } catch (e) { if (e.auth) throw e; }
    const dom = (p.targets?.production?.alias || [])[0] || p.alias?.[0]?.domain;
    out.push({ id: p.id, name: p.name, kind: 'deployment', url: dom ? 'https://' + dom : null, repo: p.link?.type === 'github' ? `${p.link.org}/${p.link.repo}` : null, vars });
  } return out;
}
async function render(c) {
  const b = col.BASE.render(), d = await col.http(`${b}/services?limit=100`, { token: c.token }); const out = [];
  for (const w of d || []) {
    const s = w.service || w; if (c.config.serviceId && s.id !== c.config.serviceId) continue;
    let vars = []; try { const e = await col.http(`${b}/services/${s.id}/env-vars?limit=100`, { token: c.token }); vars = (e || []).map((x) => ({ key: (x.envVar || x).key, value: (x.envVar || x).value })); } catch (e) { if (e.auth) throw e; }
    out.push({ id: s.id, name: s.name, kind: 'deployment', url: s.serviceDetails?.url || null, repo: s.repo ? s.repo.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '') : null, vars });
  } return out;
}
async function netlify(c) {
  const b = col.BASE.netlify(), s = await col.http(`${b}/sites/${c.config.siteId}`, { token: c.token });
  const env = s.build_settings?.env || {}; return [{ id: s.id || c.config.siteId, name: s.name, kind: 'deployment', url: s.ssl_url || s.url || null, repo: (s.build_settings?.repo_url || '').replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '') || null, vars: Object.keys(env).map((k) => ({ key: k, value: env[k] })) }];
}
async function heroku(c) {
  const b = col.BASE.heroku(), h = { accept: 'application/vnd.heroku+json; version=3' };
  const a = await col.http(`${b}/apps/${c.config.app}`, { token: c.token, headers: h }); let vars = [];
  try { const cv = await col.http(`${b}/apps/${c.config.app}/config-vars`, { token: c.token, headers: h }); vars = Object.keys(cv).map((k) => ({ key: k, value: cv[k] })); } catch (e) { if (e.auth) throw e; }
  return [{ id: a.id || c.config.app, name: a.name, kind: 'deployment', url: a.web_url || null, repo: null, vars }];
}
async function supabase(c) {
  const b = col.BASE.supabase(), d = await col.http(`${b}/projects`, { token: c.token });
  return (d || []).filter((p) => !c.config.projectRef || p.id === c.config.projectRef).map((p) => ({ id: p.id, name: p.name, kind: 'database', url: `https://${p.id}.supabase.co`, repo: null, vars: [], region: p.region }));
}
async function github(c) { const b = col.BASE.github(), r = await col.http(`${b}/repos/${c.config.repo}`, { token: c.token, headers: { accept: 'application/vnd.github+json' } }); return [{ id: r.full_name, name: r.full_name, kind: 'repo', url: r.html_url, repo: null, vars: [], private: !!r.private }]; }
const FETCH = { vercel, render, netlify, heroku, supabase, github };

async function discoverOne(collectorId, by = 'system') {
  const c = col.tokenFor(collectorId); if (!c) throw new Error('connection not found'); if (!FETCH[c.platform]) throw new Error('discovery not supported for ' + c.platform);
  const items = await FETCH[c.platform](c), src = 'discover:' + collectorId;
  graph.removeBySource(src);
  const P = c.platform, made = { nodes: 0, edges: 0 };
  for (const it of items) {
    const type = it.kind === 'repo' ? 'repo' : it.kind === 'database' ? 'database' : 'deployment';
    const id = it.kind === 'repo' ? sid('github', 'repo', it.id) : sid(P, it.kind === 'database' ? 'project' : 'service', it.name);
    graph.upsertNode({ id, type, provider: P, name: it.name, meta: { externalId: it.id, host: H(it.url), region: it.region, private: it.private, collector: collectorId }, source: src, confidence: 'verified' }); made.nodes++;
    if (it.repo) { const rid = sid('github', 'repo', it.repo); if (!graph.node(rid)) graph.upsertNode({ id: rid, type: 'repo', provider: 'github', name: it.repo, source: src, confidence: 'verified' }); graph.upsertEdge({ src: id, dst: rid, kind: 'built_from', confidence: 'verified', evidence: `${P} reports this service is built from ${it.repo}`, source: src }); made.edges++; }
    for (const v of it.vars) {
      if (!SECRETISH.test(v.key) && !PATTERNS.some(([re]) => re.test(v.key))) continue; // skip plain config like NODE_ENV
      const secId = sid('secret', P, it.name, v.key), host = v.value ? H(String(v.value)) : null;
      graph.upsertNode({ id: secId, type: 'secret', provider: P, name: `${it.name}:${v.key}`, meta: { variable: v.key, host }, source: src, confidence: 'verified' });
      graph.upsertEdge({ src: id, dst: secId, kind: 'holds_secret', confidence: 'verified', evidence: `variable ${v.key} is set on ${it.name}`, source: src }); made.nodes++; made.edges++;
      let hit = null;
      if (host) hit = graph.nodes().find((n) => n.id !== id && n.type !== 'secret' && n.meta?.host === host) || graph.nodes().find((n) => n.provider === 'supabase' && n.type === 'database' && host.endsWith('.supabase.co') && host.startsWith(String(n.meta?.externalId || '~').toLowerCase()));
      if (hit) { graph.upsertEdge({ src: secId, dst: hit.id, kind: 'grants_access', confidence: 'verified', evidence: `URL host ${host} matches ${hit.name}`, source: src }); made.edges++; continue; }
      const pat = PATTERNS.find(([re]) => re.test(v.key)); if (!pat) continue;
      const kind = pat[1], targets = kind === 'supabase' ? graph.nodes().filter((n) => n.provider === 'supabase' && n.type === 'database') : [];
      if (targets.length) for (const t of targets) { graph.upsertEdge({ src: secId, dst: t.id, kind: 'grants_access', confidence: 'inferred', evidence: `variable name ${v.key} suggests Supabase${targets.length > 1 ? ' (ambiguous: ' + targets.length + ' projects)' : ''}`, source: src }); made.edges++; }
      else { const xid = 'external:' + kind; graph.upsertNode({ id: xid, type: 'external', provider: kind, name: kind, source: 'inferred', confidence: 'inferred' }); graph.upsertEdge({ src: secId, dst: xid, kind: 'grants_access', confidence: 'inferred', evidence: `variable name ${v.key} suggests ${kind}`, source: src }); made.edges++; }
    }
  }
  audit.log(by, 'RZ_DISCOVERED', { collector: collectorId, platform: P, items: items.length });
  return { platform: P, items: items.length, ...made };
}
async function discoverAll(by = 'system') {
  const res = []; const L = col.list().filter((c) => FETCH[c.platform]);
  L.sort((a, b) => (b.platform === 'supabase') - (a.platform === 'supabase')); // projects first so links resolve
  for (const c of L) { try { res.push({ id: c.id, name: c.name, ok: true, ...(await discoverOne(c.id, by)) }); } catch (e) { res.push({ id: c.id, name: c.name, ok: false, error: String(e.message).slice(0, 160) }); } }
  return { results: res, summary: graph.summary() };
}
module.exports = { discoverOne, discoverAll, FETCH, PATTERNS };
