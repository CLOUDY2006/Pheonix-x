'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off'; process.env.PHOENIX_VERIFY_ALLOW_PRIVATE = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const app = require('../server/index');
const config = require('../server/core/config');
const rz = require('../server/resilience');

let base, mock, mbase, sess; const calls = []; let appOk = true, oldKeyAccepted = true;
const SUPA = 'abcdref123';
async function api(method, path, body) { const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', cookie: sess.cookie, 'x-csrf-token': sess.csrf }, body: body ? JSON.stringify(body) : undefined }); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; } return { status: r.status, body: j }; }
test.before(async () => {
  mock = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), p = u.pathname, j = (o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.method !== 'GET') calls.push(req.method + ' ' + p);
    if (p === '/supabase/projects') return j([{ id: SUPA, name: 'shop-db', region: 'ap-south-1' }]);
    if (p === `/supabase/projects/${SUPA}/database/backups`) return j({ backups: [{ inserted_at: new Date().toISOString(), status: 'COMPLETED' }], pitr_enabled: false });
    if (p === '/render/services') return j([{ service: { id: 'srv-api', name: 'api', repo: 'https://github.com/acme/web', serviceDetails: { url: 'https://api.example.com' } } }]);
    if (p === '/render/services/srv-api/env-vars') return j([{ envVar: { key: 'SUPABASE_SERVICE_KEY', value: 'SECRET-VALUE-1' } }, { envVar: { key: 'SUPABASE_URL', value: `https://${SUPA}.supabase.co` } }, { envVar: { key: 'NODE_ENV', value: 'production' } }]);
    if (p === '/render/services/srv-api/deploys' && req.method === 'GET') return j([{ deploy: { id: 'dep-old' } }]);
    if (p === '/render/services/srv-api/deploys' && req.method === 'POST') return j({ id: 'dep-new' }, 201);
    if (p === '/render/services/srv-api/rollback') return j({ ok: true });
    if (/^\/gh\/repos\/acme\/web\/(secret-scanning\/alerts|keys|events)$/.test(p)) return j([]);
    if (p === '/gh/repos/acme/web') return j({ full_name: 'acme/web', html_url: 'https://github.com/acme/web', private: true });
    if (p === '/app/health') return appOk ? j({ ok: true, error_rate: 0.01 }) : j({ ok: false }, 503);
    if (p === '/app/secure') return oldKeyAccepted ? j({ ok: 1 }) : j({ error: 'no' }, 401);
    j({ message: 'nope' }, 404);
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r)); mbase = 'http://127.0.0.1:' + mock.address().port;
  Object.assign(process.env, { PHOENIX_API_SUPABASE: mbase + '/supabase', PHOENIX_API_RENDER: mbase + '/render', PHOENIX_API_GITHUB: mbase + '/gh' });
  app.boot(); await new Promise((r) => app.server.listen(0, '127.0.0.1', r)); base = 'http://127.0.0.1:' + app.server.address().port;
  const r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'phoenix-demo' }) }); const j = await r.json();
  sess = { cookie: r.headers.get('set-cookie').split(';')[0], csrf: j.csrf };
});
test.after(() => { app.server.close(); mock.close(); require('../server/core/persist').stop(); });

test('connect providers, discover, and build a graph with verified vs inferred links (env VALUES are never stored)', async () => {
  for (const [platform, config_] of [['supabase', {}], ['render', {}], ['github', { repo: 'acme/web' }]]) { const r = await api('POST', '/api/collectors', { platform, token: 'tok_' + platform + '_12345', config: config_ }); assert.equal(r.status, 201, JSON.stringify(r.body)); }
  const d = await api('POST', '/api/resilience/discover'); assert.equal(d.status, 200); assert.ok(d.body.results.every((x) => x.ok), JSON.stringify(d.body.results));
  const g = (await api('GET', '/api/resilience/graph')).body, ids = g.nodes.map((n) => n.id);
  assert.ok(ids.includes(`supabase:project:shop-db`) && ids.includes('render:service:api') && ids.includes('github:repo:acme/web'));
  const E = (src, dst) => g.edges.find((e) => e.src.includes(src) && e.dst === dst);
  assert.equal(E('render:service:api', 'github:repo:acme/web').confidence, 'verified');
  assert.equal(E('supabase_url', 'supabase:project:shop-db').confidence, 'verified', 'URL host matched the project ref');
  assert.equal(E('supabase_service_key', 'supabase:project:shop-db').confidence, 'inferred', 'name-pattern link');
  assert.ok(!ids.some((i) => i.includes('node_env')), 'plain config is skipped');
  assert.ok(!JSON.stringify(g).includes('SECRET-VALUE-1'), 'values never stored');
});

test('blast radius: compromised Supabase project reaches secrets, the service and what must be redeployed', async () => {
  const b = (await api('POST', '/api/resilience/blast', { target: 'shop-db' })).body;
  assert.ok(b.connectedDeployments.includes('api')); assert.ok(b.exposedSecrets.some((s) => /SUPABASE_SERVICE_KEY/.test(s)));
  assert.equal(b.needsRedeploy[0].name, 'api'); assert.ok(b.counts.inferred > 0 && b.caveat, 'inferred links are labelled');
  assert.ok(b.affected.find((a) => a.type === 'deployment').path.length >= 3); assert.equal(b.affected.find((a) => a.type === 'deployment').confidence, 'verified', 'the verified route (URL host match) wins over the inferred one');
});

test('rehearsal: NOT_READY without checks; readiness rises once recovery can be proven; nothing is changed', async () => {
  const before = calls.length; const r1 = (await api('POST', '/api/resilience/rehearse', { scenario: 'credential', target: 'shop-db' })).body;
  assert.equal(r1.verdict, 'NOT_READY'); assert.ok(r1.blockers.some((x) => /proven/.test(x))); assert.ok(r1.missing.length > 0); assert.equal(r1.nothingChanged, true); assert.equal(calls.length, before, 'rehearsal made no write calls');
  assert.ok(r1.plan.some((s) => s.kind === 'manual' && s.link) && r1.plan.at(-1).phase === 'verify'); assert.ok(r1.estimate.minutes > 0 && r1.estimate.interruptions.length === 1);
  assert.ok(r1.checks.find((c) => c.id === 'backup').detail.includes('latest completed backup'), 'Supabase backups read from the provider API');
  await api('POST', '/api/resilience/checks', { name: 'API health', type: 'http', config: { url: mbase + '/app/health', contains: 'ok' } });
  await api('POST', '/api/resilience/checks', { name: 'Error rate', type: 'json_value', config: { url: mbase + '/app/health', path: 'error_rate', op: '<=', value: 0.02 } });
  const bad = await api('POST', '/api/resilience/checks', { name: 'Old key refused', type: 'rejects_credential', config: { url: mbase + '/app/secure' } }); assert.equal(bad.status, 400, 'needs the credential value');
  const ok = await api('POST', '/api/resilience/checks', { name: 'Old key refused', type: 'rejects_credential', config: { url: mbase + '/app/secure' }, secret: 'OLD-LEAKED-KEY' }); assert.equal(ok.status, 201); assert.ok(!JSON.stringify(ok.body).includes('OLD-LEAKED-KEY'));
  const r2 = (await api('POST', '/api/resilience/rehearse', { scenario: 'credential', target: 'shop-db' })).body;
  assert.notEqual(r2.verdict, 'NOT_READY'); assert.ok(r2.score > r1.score, `${r2.score} > ${r1.score}`);
});

test('verification engine: real probes decide pass/fail; the old credential must be refused', async () => {
  const v1 = (await api('POST', '/api/resilience/verify', {})).body; assert.equal(v1.verdict, 'FAILED'); assert.match(v1.results.find((x) => x.type === 'rejects_credential').detail, /still ACCEPTED/); assert.match(v1.sha256, /^[a-f0-9]{64}$/);
  oldKeyAccepted = false; const v2 = (await api('POST', '/api/resilience/verify', {})).body; assert.equal(v2.verdict, 'PASSED');
  appOk = false; assert.equal((await api('POST', '/api/resilience/verify', {})).body.verdict, 'FAILED'); appOk = true;
});
test('verification SSRF guard blocks internal targets when private access is not allowed', async () => {
  const v = rz.verify; assert.ok(v.privateIp('169.254.169.254') && v.privateIp('10.0.0.5') && v.privateIp('::1') && !v.privateIp('8.8.8.8'));
  delete process.env.PHOENIX_VERIFY_ALLOW_PRIVATE; await assert.rejects(v.guard('http://127.0.0.1/x'), /https required/); await assert.rejects(v.guard('https://127.0.0.1/x'), /private/); await assert.rejects(v.guard('https://169.254.169.254/latest'), /private/); process.env.PHOENIX_VERIFY_ALLOW_PRIVATE = '1';
});

test('safe execution: preview → admin approval → dry-run by default → human steps → real redeploy → auto-verify → rollback', async () => {
  const pl = (await api('POST', '/api/resilience/plans', { scenario: 'credential', target: 'shop-db' })).body; assert.equal(pl.status, 'preview');
  for (const k of ['changes', 'affectedServices', 'risks', 'reversal', 'verification']) assert.ok(pl.preview[k].length, k);
  assert.equal((await api('POST', `/api/resilience/plans/${pl.id}/execute`)).status, 400, 'cannot run before approval');
  assert.equal((await api('POST', `/api/resilience/plans/${pl.id}/approve`)).status, 200);
  const rid = pl.steps.find((s) => s.phase === 'redeploy'); assert.equal(rid.kind, 'manual', 'redeploy needs write access first');
  const col = (await api('GET', '/api/collectors')).body.collectors.find((c) => c.platform === 'render'); assert.equal((await api('POST', `/api/collectors/${col.id}/write`, { enabled: true })).status, 200);
  const pl2 = (await api('POST', '/api/resilience/plans', { scenario: 'credential', target: 'shop-db' })).body; await api('POST', `/api/resilience/plans/${pl2.id}/approve`); assert.equal(pl2.steps.find((s) => s.phase === 'redeploy').kind, 'auto');
  // dry-run (default)
  assert.equal(config.connectorDryRun, true); const before = calls.length; let p = (await api('POST', `/api/resilience/plans/${pl2.id}/execute`)).body; assert.equal(p.status, 'waiting_on_human'); assert.equal(calls.length, before);
  for (const s of p.steps.filter((x) => x.kind === 'manual')) p = (await api('POST', `/api/resilience/plans/${pl2.id}/steps/${s.id}`, { state: 'done' })).body;
  assert.equal(p.status, 'dry_run_complete'); assert.equal(calls.length, before, 'dry-run made no write calls'); assert.ok(p.steps.find((s) => s.phase === 'redeploy').log[0].startsWith('DRY-RUN'));
  // real
  config.connectorDryRun = false; const pl3 = (await api('POST', '/api/resilience/plans', { scenario: 'credential', target: 'shop-db' })).body; await api('POST', `/api/resilience/plans/${pl3.id}/approve`);
  p = (await api('POST', `/api/resilience/plans/${pl3.id}/execute`)).body; assert.equal(p.status, 'waiting_on_human'); assert.equal((await api('POST', `/api/resilience/plans/${pl3.id}/steps/${p.steps.find((s) => s.phase === 'contain').id}`, { state: 'skipped' })).status, 400, 'containment cannot be skipped');
  for (const s of p.steps.filter((x) => x.kind === 'manual')) p = (await api('POST', `/api/resilience/plans/${pl3.id}/steps/${s.id}`, { state: 'done' })).body;
  assert.equal(p.status, 'recovered_verified', JSON.stringify(p.steps.map((s) => [s.id, s.status, s.log]))); assert.ok(calls.includes('POST /render/services/srv-api/deploys')); const rs = p.steps.find((s) => s.phase === 'redeploy'); assert.equal(rs.prev, 'dep-old'); assert.equal(p.steps.at(-1).verification.verdict, 'PASSED');
  const u = await api('POST', `/api/resilience/plans/${pl3.id}/steps/${rs.id}/undo`); assert.equal(u.status, 200); assert.ok(calls.includes('POST /render/services/srv-api/rollback'));
  config.connectorDryRun = true;
});

test('incident memory: records, retrieves similar incidents with the earlier procedure, and the evidence bundle is tamper-evident', async () => {
  const mk = (id, extra = {}) => ({ id, title: 'Leaked key abuse', severity: 'High', alerts: [{ rule: 'R-KEY-LEAK', category: 'Credential Access', mitre: [{ id: 'T1552' }], evidenceSummary: 'key used from new ip', riskScore: 80 }], entities: { ips: ['1.2.3.4'], users: [] }, containment: [{ type: 'revoke_token', target: 'svc-key', status: 'executed', approvedBy: 'ai:balanced', tier: 'automatic' }], recovery: { tasks: [{ title: 'Rotate the service key', status: 'done', kind: 'rotate' }] }, verification: { passed: true, failed: 0 }, evidence: { sha256: 'ab'.repeat(32), count: 3 }, lessons: ['Rotate keys quarterly'], ...extra });
  rz.memory.record(mk('INC-A')); const sim = rz.memory.similar(mk('INC-B'));
  assert.equal(sim.length, 1); assert.equal(sim[0].incidentId, 'INC-A'); assert.ok(sim[0].similarity >= 90); assert.ok(sim[0].procedure.some((x) => /revoke_token/.test(x)) && sim[0].procedure.includes('Rotate the service key'));
  assert.equal(rz.memory.similar({ id: 'X', alerts: [{ rule: 'R-OTHER', category: 'Impact', mitre: [] }], entities: {} }).length, 0);
  const b = (await api('GET', '/api/resilience/memory/INC-A')).body; assert.equal(b.integrity.stored, b.integrity.recomputed);
});

test('incidents get blast radius + similar history automatically, and are remembered when resolved', async () => {
  const h = require('./helpers'); const inc = await h.run('ransomware'); await h.until(() => inc.state === 'RESOLVED', 20000);
  assert.ok(Array.isArray(inc.similar)); assert.ok(rz.memory.get(inc.id), 'resolved incidents are stored'); assert.equal(rz.memory.bundle(inc.id).integrity.stored, rz.memory.bundle(inc.id).integrity.recomputed);
});

test('chat understands resilience commands', async () => {
  const say = async (m) => (await api('POST', '/api/chat', { message: m, text: m })).body.reply;
  assert.match(await say('what depends on shop-db'), /Blast radius of shop-db[\s\S]*api/);
  assert.match(await say('rehearse shop-db'), /nothing was changed[\s\S]*\/100/);
  assert.match(await say('are we ready'), /\/100/);
  oldKeyAccepted = false; assert.match(await say('verify recovery'), /PASSED/); oldKeyAccepted = true;
  assert.match(await say('similar incidents'), /resembles|no similar|No incidents/i);
  assert.match(await say('rehearse nothingatall'), /can't find/);
});
