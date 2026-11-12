'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off'; process.env.PHOENIX_CORRELATE_MS = '500';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto'); const zlib = require('zlib'); const fs = require('fs'); const os = require('os'); const path = require('path');
const { spawn } = require('child_process');
// async: the server runs in THIS process, so a blocking spawnSync would deadlock it
const spawnSync = (cmd, args, o) => new Promise((res) => { const c = spawn(cmd, args, { env: o.env }); let out = '', err = ''; c.stdout.on('data', (d) => (out += d)); c.stderr.on('data', (d) => (err += d)); c.on('close', (status) => res({ status, stdout: out, stderr: err })); });
const P = require('../server/ingest/platforms');
const app = require('../server/index');
let base, admin;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
test.before(async () => { app.boot(); await new Promise((r) => app.server.listen(0, '127.0.0.1', r)); base = 'http://127.0.0.1:' + app.server.address().port; const r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'phoenix-demo' }) }); admin = { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; });
test.after(() => { app.server.close(); require('../server/core/persist').stop(); });
async function call(method, p, { body, raw, headers = {}, s } = {}) { const r = await fetch(base + p, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(s ? { cookie: s.cookie, 'x-csrf-token': s.csrf } : {}), ...headers }, body: raw !== undefined ? raw : body ? JSON.stringify(body) : undefined }); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; } return { status: r.status, body: j, headers: r.headers }; }
const mkKey = async (format, extra = {}) => (await call('POST', '/api/keys', { s: admin, body: { name: 'k-' + format + Math.random().toString(36).slice(2, 5), format, ...extra } })).body;
const events = async () => (await call('GET', '/api/events?limit=5000', { s: admin })).body;

// ------------------------------------------------------------------ normalizers
test('Vercel log drain: requests, WAF blocks, auth failures; webhooks: deploys and risky changes', () => {
  const ev = P.vercel([
    { id: 'l1', source: 'edge', timestamp: 1762500000000, projectName: 'shop', proxy: { clientIp: '203.0.113.5', method: 'POST', host: 'shop.example', path: '/api/auth/login', statusCode: 401, userAgent: ['curl/8'], region: 'iad1', timestamp: 1762500000000 } },
    { id: 'l2', source: 'firewall', timestamp: 1762500001000, proxy: { clientIp: '203.0.113.6', method: 'GET', host: 'shop.example', path: '/.env', statusCode: 403, userAgent: ['x'], region: 'iad1', wafAction: 'deny', wafRuleId: 'sqli' } },
    { id: 'l3', source: 'lambda', level: 'info', message: 'hello' }, { id: 'l4', source: 'lambda', level: 'error', message: 'boom', path: '/api/x', timestamp: 1762500002000 }]);
  assert.deepEqual(ev.map((e) => e.type), ['web_request', 'login_failed', 'waf_block', 'web_request', 'app_error']);
  assert.equal(ev[0].ip, '203.0.113.5'); assert.equal(ev[0].outcome, 'failure'); assert.equal(ev[2].details.rule, 'sqli');
  const d = P['vercel-webhook']({ id: 'w1', type: 'deployment.error', createdAt: 1762500000000, payload: { deployment: { name: 'shop' }, user: { username: 'dev1' } } });
  assert.equal(d[0].type, 'deploy_event'); assert.equal(d[0].outcome, 'failure');
  const c = P['vercel-webhook']({ type: 'domain.created', createdAt: 1762500000000, payload: { domain: { name: 'evil.example' }, user: { username: 'dev1' } } });
  assert.equal(c[0].details.change, 'domain_changed'); assert.deepEqual(P['vercel-webhook']({ type: 'something.unknown' }), []);
});
test('Heroku Logplex octet-counted drain: router lines and API audit lines', () => {
  const m1 = '<158>1 2026-11-07T10:00:00+00:00 host heroku router - at=info method=POST path="/login" host=app.example request_id=r1 fwd="9.9.9.9" dyno=web.1 connect=0ms service=3ms status=401 bytes=10';
  const m2 = '<40>1 2026-11-07T10:00:01+00:00 host heroku api - Set STRIPE_KEY config vars by user dev@corp.example';
  const m3 = '<40>1 2026-11-07T10:00:02+00:00 host heroku api - Deploy abc1234 by user dev@corp.example';
  const body = [m1, m2, m3].map((m) => Buffer.byteLength(m) + ' ' + m).join('');
  assert.equal(P.logplexFrames(body).length, 3);
  const ev = P.heroku({ lines: body });
  assert.deepEqual(ev.map((e) => e.type), ['web_request', 'login_failed', 'platform_change', 'deploy_event']);
  assert.equal(ev[0].ip, '9.9.9.9'); assert.equal(ev[2].details.change, 'env_var_changed'); assert.equal(ev[2].details.actor, 'dev@corp.example');
});
test('Netlify, Railway, Render webhooks and Render log-stream lines', () => {
  const n = P.netlify({ id: 'd1', site_id: 's1', name: 'blog', state: 'error', context: 'production', branch: 'main', commit_ref: 'abc', committer: 'sam', created_at: '2026-11-07T10:00:00Z' }); assert.equal(n[0].outcome, 'failure'); assert.equal(n[0].details.actor, 'sam');
  assert.equal(P.railway({ type: 'DEPLOY', status: 'CRASHED', project: { name: 'p' }, service: { name: 'api' }, deployment: { id: 'x' } })[0].outcome, 'failure');
  assert.equal(P['render-webhook']({ type: 'deploy_ended', timestamp: '2026-11-07T10:00:00Z', data: { id: 'dep-1', serviceName: 'api', status: 'failed' } })[0].outcome, 'failure');
  const ev = P.render({ lines: ['<6>1 2026-11-07T10:00:00Z api web-1 123 web - {"ip":"198.51.100.4","path":"/admin","status":404,"method":"GET"}', '<6>1 2026-11-07T10:00:01Z api web-1 123 web - just some log text'] });
  assert.equal(ev.length, 1); assert.equal(ev[0].ip, '198.51.100.4');
});
test('Cloudflare Logpush (http_requests + firewall_events), GitHub events, nginx lines', () => {
  const cf = P.cloudflare([{ content: 'tests' }, { ClientIP: '198.51.100.9', ClientRequestHost: 'a.example', ClientRequestMethod: 'GET', ClientRequestURI: '/wp-login.php', EdgeResponseStatus: 404, ClientCountry: 'ru', EdgeStartTimestamp: '2026-11-07T10:00:00Z' }, { Action: 'block', ClientIP: '198.51.100.9', ClientRequestPath: '/x', RuleID: 'r1', Datetime: '2026-11-07T10:00:01Z' }, { Action: 'log', ClientIP: '1.1.1.1' }]);
  assert.deepEqual(cf.map((e) => e.type), ['web_request', 'waf_block']); assert.equal(cf[0].geo.country, 'ru');
  assert.equal(P.github({ __event: 'secret_scanning_alert', action: 'created', repository: { full_name: 'o/r' }, sender: { login: 'bob' }, alert: { secret_type_display_name: 'AWS key' } })[0].details.change, 'secret_exposed');
  assert.equal(P.github({ __event: 'repository', action: 'publicized', repository: { full_name: 'o/r' }, sender: { login: 'bob' } })[0].details.change, 'repo_public');
  assert.deepEqual(P.github({ __event: 'ping' }), []); assert.deepEqual(P.github({ __event: 'issues', action: 'opened' }), []);
  const ng = P.nginx({ lines: '203.0.113.7 - - [07/Nov/2026:10:00:00 +0000] "GET /.git/config HTTP/1.1" 404 153 "-" "Mozilla/5.0"\ngarbage line' }); assert.equal(ng.length, 1); assert.equal(ng[0].ts, '2026-11-07T10:00:00.000Z'); assert.equal(ng[0].resource, '/.git/config');
});

// ------------------------------------------------------------------ HTTP: auth modes, signatures, encodings
test('key accepted as header, Basic password, and URL token; wrong key rejected; format binding honoured', async () => {
  const k = await mkKey('nginx'); const line = '203.0.113.7 - - [07/Nov/2026:10:00:00 +0000] "GET /a HTTP/1.1" 404 1 "-" "ua"';
  const body = { lines: [line] };
  assert.equal((await call('POST', '/api/ingest/nginx', { body, headers: { 'x-api-key': k.key } })).body.accepted, 1);
  assert.equal((await call('POST', '/api/ingest/nginx', { body, headers: { authorization: 'Basic ' + Buffer.from('phoenix:' + k.key).toString('base64') } })).status, 200);
  assert.equal((await call('POST', '/api/hook/' + k.key, { body })).body.accepted, 1, 'hook URL uses the key\'s own format');
  assert.equal((await call('POST', '/api/hook/phx_wrong', { body })).status, 401);
  assert.equal((await call('POST', '/api/ingest/heroku', { body, headers: { 'x-api-key': k.key } })).status, 403, 'nginx key cannot post heroku data');
  assert.equal((await call('GET', '/api/hook/' + k.key)).body.ok, true, 'GET = reachability check');
});
test('Vercel: signature enforced when a secret is set; verify handshake header; NDJSON body', async () => {
  const k = await mkKey('vercel', { signingSecret: 's3cret', verifyToken: 'verif-123' });
  const log = { id: 'v1', source: 'edge', timestamp: Date.now(), proxy: { clientIp: '203.0.113.50', method: 'GET', host: 'x.example', path: '/nope', statusCode: 404, userAgent: ['u'], region: 'r', timestamp: Date.now() } };
  const nd = JSON.stringify(log) + '\n' + JSON.stringify({ ...log, id: 'v2' }) + '\n';
  const sig = crypto.createHmac('sha1', 's3cret').update(nd).digest('hex');
  const bad = await call('POST', '/api/hook/' + k.key, { raw: nd, headers: { 'content-type': 'application/x-ndjson', 'x-vercel-signature': 'deadbeef' } }); assert.equal(bad.status, 401);
  const none = await call('POST', '/api/hook/' + k.key, { raw: nd, headers: { 'content-type': 'application/x-ndjson' } }); assert.equal(none.status, 401);
  const ok = await call('POST', '/api/hook/' + k.key, { raw: nd, headers: { 'content-type': 'application/x-ndjson', 'x-vercel-signature': sig } }); assert.equal(ok.status, 200); assert.equal(ok.body.accepted, 2);
  const hs = await call('GET', '/api/hook/' + k.key); assert.equal(hs.headers.get('x-vercel-verify'), 'verif-123'); assert.equal(hs.status, 200);
  assert.equal((await call('POST', '/api/hook/' + k.key, { raw: nd, headers: { 'content-type': 'application/x-ndjson', 'x-vercel-signature': sig } })).body.duplicates, 2, 'redelivery is deduplicated');
});
test('GitHub (HMAC-SHA256) and Netlify (JWS HS256) signatures', async () => {
  const kg = await mkKey('github', { signingSecret: 'gh-secret' }); const payload = JSON.stringify({ action: 'created', repository: { full_name: 'o/r' }, sender: { login: 'mallory' }, alert: { secret_type_display_name: 'Stripe key' } });
  const gs = 'sha256=' + crypto.createHmac('sha256', 'gh-secret').update(payload).digest('hex');
  assert.equal((await call('POST', '/api/hook/' + kg.key, { raw: payload, headers: { 'content-type': 'application/json', 'x-github-event': 'secret_scanning_alert', 'x-hub-signature-256': 'sha256=00' } })).status, 401);
  const g = await call('POST', '/api/hook/' + kg.key, { raw: payload, headers: { 'content-type': 'application/json', 'x-github-event': 'secret_scanning_alert', 'x-hub-signature-256': gs } }); assert.equal(g.body.accepted, 1);
  const kn = await mkKey('netlify', { signingSecret: 'jws-secret' }); const dep = JSON.stringify({ id: 'dep9', site_id: 's', name: 'blog', state: 'ready', committer: 'sam' });
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url'); const h = b64({ alg: 'HS256', typ: 'JWT' }), p = b64({ iss: 'netlify', sha256: crypto.createHash('sha256').update(dep).digest('hex') });
  const jws = h + '.' + p + '.' + crypto.createHmac('sha256', 'jws-secret').update(h + '.' + p).digest('base64url');
  assert.equal((await call('POST', '/api/hook/' + kn.key, { raw: dep, headers: { 'content-type': 'application/json', 'x-webhook-signature': jws } })).body.accepted, 1);
  assert.equal((await call('POST', '/api/hook/' + kn.key, { raw: dep + ' ', headers: { 'content-type': 'application/json', 'x-webhook-signature': jws } })).status, 401, 'body tampering breaks the sha256 claim');
});
test('Cloudflare: gzip NDJSON and the destination test payload', async () => {
  const k = await mkKey('cloudflare'); assert.equal((await call('POST', '/api/hook/' + k.key, { raw: '{"content":"tests"}', headers: { 'content-type': 'application/json' } })).status, 200);
  const nd = [1, 2, 3].map((i) => JSON.stringify({ ClientIP: '198.51.100.' + i, ClientRequestHost: 'a.example', ClientRequestMethod: 'GET', ClientRequestURI: '/x' + i, EdgeResponseStatus: 404, EdgeStartTimestamp: new Date().toISOString() })).join('\n');
  const r = await fetch(base + '/api/hook/' + k.key, { method: 'POST', headers: { 'content-encoding': 'gzip', 'content-type': 'application/x-ndjson' }, body: zlib.gzipSync(nd) }); assert.equal((await r.json()).accepted, 3);
});
test('connection test event raises the key\'s received counter; catalog is served', async () => {
  const k = await mkKey('generic'); assert.equal((await call('POST', `/api/keys/${k.id}/test`, { s: admin, body: {} })).status, 200);
  const row = (await call('GET', '/api/keys', { s: admin })).body.keys.find((x) => x.id === k.id); assert.equal(row.received, 1); assert.ok(row.lastUsed === null || row.lastUsed);
  const cat = (await call('GET', '/api/platforms', { s: admin })).body; for (const id of ['vercel', 'render', 'heroku', 'netlify', 'railway', 'cloudflare', 'github', 'vps', 'aws', 'other']) assert.ok(cat.find((p) => p.id === id), id);
  for (const p of cat) for (const m of p.methods) { assert.ok(require('../server/ingest/normalize').FORMATS.includes(m.format), `${p.id}/${m.id} format ${m.format}`); assert.ok(m.steps.length); }
});

// ------------------------------------------------------------------ detection end-to-end
const state = async () => (await call('GET', '/api/state', { s: admin })).body;
test('web scanner from a Vercel drain becomes an incident (R-WEB-PROBE)', async () => {
  const k = await mkKey('vercel'); const now = Date.now(); const paths = ['/.env', '/.git/config', '/wp-admin/', '/phpmyadmin/', '/actuator/health', '/backup.zip'];
  const logs = paths.map((p, i) => ({ id: 'sc' + i, source: 'edge', timestamp: now + i, proxy: { clientIp: '198.51.100.99', method: 'GET', host: 'shop.example', path: p, statusCode: 404, userAgent: ['zgrab'], region: 'iad1', timestamp: now + i } }));
  assert.equal((await call('POST', '/api/hook/' + k.key, { body: logs })).body.accepted, 6);
  const inc = await (async () => { for (let i = 0; i < 60; i++) { const s = await state(); const f = s.incidents.find((x) => x.categories.includes('Web Reconnaissance')); if (f) return f; await sleep(250); } })();
  assert.ok(inc, 'incident opened'); assert.equal(inc.origin, 'ingested');
  const full = (await call('GET', `/api/incidents/${inc.id}`, { s: admin })).body; assert.ok(full.alerts.some((a) => a.rule === 'R-WEB-PROBE' && a.affected.ips.includes('198.51.100.99')));
});
test('credential stuffing via HTTP 401s, and injection payloads, are detected', async () => {
  const k = await mkKey('generic'); const ip = '198.51.100.120'; const evs = [];
  for (let i = 0; i < 8; i++) evs.push({ source: 'authentication', type: 'login_failed', ip, outcome: 'failure', details: { via: 'http-status' } });
  for (let i = 0; i < 4; i++) evs.push({ source: 'network', type: 'web_request', ip: '198.51.100.121', host: 'a.example', resource: "/search?q=1' or '1'='1&x=" + i, details: { status: 200, method: 'GET' } });
  assert.equal((await call('POST', '/api/hook/' + k.key, { body: { events: evs } })).body.accepted, 12);
  let cats = []; for (let i = 0; i < 60; i++) { cats = (await state()).incidents.flatMap((x) => x.categories); if (cats.includes('Brute Force') && cats.includes('Web Application Attack')) break; await sleep(250); }
  assert.ok(cats.includes('Brute Force'), 'brute force from IP-only login failures'); assert.ok(cats.includes('Web Application Attack'));
});
test('GitHub secret-scanning alert and Heroku config-var change raise platform alerts', async () => {
  const kg = await mkKey('github'); await call('POST', '/api/hook/' + kg.key, { body: { action: 'created', repository: { full_name: 'acme/api' }, sender: { login: 'carol' }, alert: { secret_type_display_name: 'AWS access key' } }, headers: { 'x-github-event': 'secret_scanning_alert' } });
  let hit; for (let i = 0; i < 60; i++) { hit = (await state()).incidents.find((x) => x.categories.includes('Credential Exposure')); if (hit) break; await sleep(250); }
  assert.ok(hit, 'credential exposure incident');
  const full = (await call('GET', `/api/incidents/${hit.id}`, { s: admin })).body; assert.match(full.alerts[0].evidenceSummary, /github: secret scanning: AWS access key by carol on acme\/api/);
  assert.ok(full.alerts[0].affected.users.length === 0, 'a GitHub login is not treated as an identity-provider user, so no account-disable is planned for it');
});

// ------------------------------------------------------------------ SDK + shipper
test('SDK: Express-style middleware, login helpers and batching reach PHOENIX', async () => {
  const { createPhoenix } = require('../public/sdk/phoenix.js'); const k = await mkKey('generic');
  const phx = createPhoenix({ url: base, key: k.key, flushMs: 0, immediate: true, onError: (e) => { throw e; } });
  const http = require('http'); const web = http.createServer((req, res) => { phx.middleware()(req, res, () => { res.statusCode = req.url.startsWith('/login') ? 401 : 200; res.end('x'); }); });
  await new Promise((r) => web.listen(0, '127.0.0.1', r)); const wb = 'http://127.0.0.1:' + web.address().port;
  await fetch(wb + '/ok'); await fetch(wb + '/login', { method: 'POST', headers: { 'x-forwarded-for': '203.0.113.77' } }); await fetch(wb + '/missing?token=secret', { headers: { 'x-forwarded-for': '203.0.113.77' } });
  phx.loginFailed({ user: 'zed', ip: '203.0.113.78' }); phx.change({ what: 'role granted: admin', actor: 'zed', resource: 'app' }); await phx.flush(); await sleep(300); web.close();
  const ev = (await events()).filter((e) => e.details?.platform === 'sdk' || e.user === 'zed');
  assert.ok(ev.some((e) => e.type === 'web_request' && e.ip === '203.0.113.77' && e.resource === '/login'), 'error response recorded');
  assert.ok(ev.some((e) => e.type === 'login_failed' && e.ip === '203.0.113.77'), '401 on /login becomes a login failure');
  assert.ok(!ev.some((e) => e.resource === '/ok'), 'successful requests are not sent by default');
  assert.ok(ev.every((e) => !String(e.resource || '').includes('secret')), 'query strings (tokens) are stripped by default');
  assert.ok(ev.some((e) => e.type === 'platform_change' && e.details.actor === 'zed'));
  const dead = createPhoenix({ url: 'http://127.0.0.1:1', key: 'x', immediate: true, timeoutMs: 300 }); dead.track({ source: 'system', type: 'x' }); await dead.flush(); // unreachable PHOENIX never throws
});
test('log shipper: ships a file, survives restart without duplicates', async () => {
  const k = await mkKey('nginx'); const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phx-ship-')); const f = path.join(dir, 'access.log');
  const L = (i) => `203.0.113.${100 + i} - - [07/Nov/2026:10:00:0${i} +0000] "GET /shipped${i} HTTP/1.1" 404 1 "-" "ua"`;
  fs.writeFileSync(f, [0, 1, 2].map(L).join('\n') + '\n');
  const run = () => spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'ship-logs.js'), '--url', base, '--key', k.key, '--format', 'nginx', '--file', f, '--from-start', '--once'], { env: { ...process.env, PHOENIX_SHIP_STATE: path.join(dir, 'state') }, encoding: 'utf8' });
  const r1 = await run(); assert.equal(r1.status, 0, r1.stderr); assert.match(r1.stdout, /shipped 3 events/);
  fs.appendFileSync(f, L(3) + '\n' + L(4).slice(0, 30)); // second line is incomplete: must wait for the newline
  const r2 = await run(); assert.match(r2.stdout, /shipped 1 events/); const shipped = (await events()).filter((e) => /^\/shipped/.test(e.resource || '')); assert.equal(shipped.length, 4);
  assert.equal((await spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'ship-logs.js'), '--url', base, '--key', 'phx_bad', '--format', 'nginx', '--file', f, '--from-start', '--once'], { env: { ...process.env, PHOENIX_SHIP_STATE: path.join(dir, 'state2') } })).status, 1, 'bad key stops the shipper with a clear error');
});
