'use strict';
// POSTURE SCAN: read-only checks that find weaknesses BEFORE an attacker does.
//  - secrets exposed to the browser (NEXT_PUBLIC_/VITE_… variables that look private)
//  - Supabase tables without row-level security (reads pg_tables through the Management API)
//  - GitHub: default branch without protection, secret scanning off
const crypto = require('crypto'); const db = require('../core/db'); const audit = require('../core/audit');
const graph = require('./graph'); const col = require('../collectors');

const CLIENT = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_)/i, PRIVATE = /(SECRET|PRIVATE|SERVICE_ROLE|SERVICEROLE|PASSWORD|DATABASE_URL|WEBHOOK_SIGNING|ACCESS_TOKEN|API_KEY)/i, SAFE = /(ANON|PUBLISHABLE|PUBLIC_KEY|PUBLIC_URL|SITE_KEY|CLIENT_ID|MEASUREMENT|ANALYTICS|DSN)/i;
const WEIGHT = { critical: 30, high: 15, medium: 6, low: 2, info: 0 };
async function run(by = 'system') {
  const F = [], add = (f) => F.push({ id: 'f' + (F.length + 1), ...f });
  // 1) browser-exposed secrets (verified: variable names come from the provider API)
  for (const n of graph.nodes().filter((x) => x.type === 'secret')) { const v = n.meta?.variable || ''; if (CLIENT.test(v) && PRIVATE.test(v) && !SAFE.test(v)) add({ severity: 'critical', check: 'client_exposed_secret', where: n.name, title: `${v} looks like a private secret but is exposed to the browser`, detail: `Variables starting with ${v.match(CLIENT)[0]} are bundled into public JavaScript. Anyone can read them.`, fix: 'Rename it without the public prefix, keep it server-side only, and rotate the value because it was already public.', confidence: 'verified' }); }
  // 2) Supabase RLS
  for (const n of graph.nodes().filter((x) => x.provider === 'supabase' && x.type === 'database')) {
    const c = n.meta?.collector && col.tokenFor(n.meta.collector); if (!c) continue;
    try {
      const rows = await col.http(`${col.BASE.supabase()}/projects/${n.meta.externalId}/database/query`, { token: c.token, method: 'POST', body: { query: "select tablename, rowsecurity from pg_tables where schemaname = 'public'" } });
      const open = (Array.isArray(rows) ? rows : rows.result || []).filter((r) => r.rowsecurity === false || r.rowsecurity === 'f');
      for (const t of open) add({ severity: 'critical', check: 'supabase_rls_off', where: `${n.name}.public.${t.tablename}`, title: `Table "${t.tablename}" has row-level security OFF`, detail: 'With RLS off, anyone holding your public (anon) key can read or change every row through the API.', fix: `Run: alter table public."${t.tablename}" enable row level security; then add policies for who may read/write.`, link: `https://supabase.com/dashboard/project/${n.meta.externalId}/auth/policies`, confidence: 'verified' });
      if (!open.length) add({ severity: 'info', check: 'supabase_rls_ok', where: n.name, title: 'All public tables have row-level security', detail: 'Checked via the Supabase API.', fix: '', confidence: 'verified' });
    } catch (e) { add({ severity: 'info', check: 'supabase_rls_unchecked', where: n.name, title: 'Could not check row-level security', detail: String(e.message).slice(0, 120) + '. The token may lack permission to run read-only queries.', fix: 'Check the table policies in the Supabase dashboard.', link: `https://supabase.com/dashboard/project/${n.meta.externalId}/auth/policies`, confidence: 'unknown' }); }
  }
  // 3) GitHub repository hygiene
  for (const g of col.list().filter((x) => x.platform === 'github' && x.config.repo)) {
    const c = col.tokenFor(g.id), repo = g.config.repo, H = { accept: 'application/vnd.github+json' };
    try {
      const r = await col.http(`${col.BASE.github()}/repos/${repo}`, { token: c.token, headers: H }); const br = r.default_branch || 'main';
      try { await col.http(`${col.BASE.github()}/repos/${repo}/branches/${encodeURIComponent(br)}/protection`, { token: c.token, headers: H }); }
      catch (e) { if (e.status === 404) add({ severity: 'high', check: 'github_no_branch_protection', where: `${repo}@${br}`, title: `Default branch "${br}" is not protected`, detail: 'Anyone with write access (or a stolen token) can push straight to production code, or force-push over history.', fix: 'Require pull requests and block force-pushes on this branch.', link: `https://github.com/${repo}/settings/branches`, confidence: 'verified' }); else add({ severity: 'info', check: 'github_protection_unchecked', where: repo, title: 'Could not read branch protection', detail: 'The token needs Administration (read) permission.', fix: '', confidence: 'unknown' }); }
      const ss = r.security_and_analysis?.secret_scanning?.status; if (ss === 'disabled') add({ severity: 'medium', check: 'github_secret_scanning_off', where: repo, title: 'Secret scanning is off', detail: 'Leaked keys pushed to this repository will not be detected by GitHub.', fix: 'Enable secret scanning and push protection.', link: `https://github.com/${repo}/settings/security_analysis`, confidence: 'verified' });
    } catch (e) { add({ severity: 'info', check: 'github_unchecked', where: repo, title: 'Could not check the repository', detail: String(e.message).slice(0, 120), fix: '', confidence: 'unknown' }); }
  }
  const penalty = F.reduce((s, f) => s + (WEIGHT[f.severity] || 0), 0), score = Math.max(0, 100 - penalty);
  const rep = { id: 'pos-' + crypto.randomBytes(4).toString('hex'), at: new Date().toISOString(), score, findings: F.sort((a, b) => (WEIGHT[b.severity] - WEIGHT[a.severity])), counts: F.reduce((m, f) => (m[f.severity] = (m[f.severity] || 0) + 1, m), {}), checked: { secrets: graph.nodes().filter((x) => x.type === 'secret').length, databases: graph.nodes().filter((x) => x.type === 'database').length, repos: col.list().filter((x) => x.platform === 'github').length } };
  db.get().prepare('insert into rz_runs(id,kind,ref,status,result,by,at) values(?,?,?,?,?,?,?)').run(rep.id, 'posture', null, String(score), JSON.stringify(rep), by, rep.at);
  audit.log(by, 'RZ_POSTURE_SCAN', { id: rep.id, score, critical: rep.counts.critical || 0, high: rep.counts.high || 0 }); return rep;
}
const latest = () => { const r = db.get().prepare("select result from rz_runs where kind='posture' order by at desc limit 1").get(); return r ? JSON.parse(r.result) : null; };
const history = (n = 20) => db.get().prepare("select result from rz_runs where kind='posture' order by at desc limit ?").all(n).map((r) => { const x = JSON.parse(r.result); return { id: x.id, at: x.at, score: x.score, counts: x.counts }; });
module.exports = { run, latest, history };
