'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const h = require('./helpers');
const db = require('../server/core/db');
const secrets = require('../server/core/secrets');

// One mock server pretending to be GitHub, Heroku, Vercel, Netlify and Render
let state, srv, base;
const reset = () => { state = { gh: { alerts: [], keys: [], events: [] }, heroku: '', vercel: [], netlify: [], render: { events: [], logs: [] }, authFail: false }; };
test.before(async () => {
  reset();
  srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), p = u.pathname, j = (o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (state.authFail) return j({ message: 'bad credentials' }, 401);
    if (p === '/gh/repos/acme/web/secret-scanning/alerts') return j(state.gh.alerts);
    if (p === '/gh/repos/acme/web/keys') return j(state.gh.keys);
    if (p === '/gh/repos/acme/web/events') return j(state.gh.events);
    if (p === '/heroku/apps/shop/log-sessions' && req.method === 'POST') return j({ logplex_url: base + '/heroku/logs' });
    if (p === '/heroku/logs') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(state.heroku); }
    if (p === '/vercel/v6/deployments') return j({ deployments: state.vercel });
    if (p === '/netlify/sites/s1/deploys') return j(state.netlify);
    if (p === '/render/services') return j([{ service: { id: 'srv-1', name: 'api', ownerId: 'own-1' } }]);
    if (p === '/render/services/srv-1/events') return j(state.render.events);
    if (p === '/render/logs') return j({ logs: state.render.logs });
    j({ message: 'nope' }, 404);
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); base = 'http://127.0.0.1:' + srv.address().port;
  Object.assign(process.env, { PHOENIX_API_GITHUB: base + '/gh', PHOENIX_API_HEROKU: base + '/heroku', PHOENIX_API_VERCEL: base + '/vercel', PHOENIX_API_NETLIFY: base + '/netlify', PHOENIX_API_RENDER: base + '/render' });
  db.open(':memory:');
});
test.after(() => srv.close());
const C = () => require('../server/collectors');
const evs = () => require('../server/core/events');

test('secrets: AES-256-GCM round-trips, is randomised, and rejects tampering', () => {
  const a = secrets.encrypt('ghp_supersecret'), b = secrets.encrypt('ghp_supersecret'); assert.notEqual(a, b); assert.ok(!a.includes('supersecret'));
  assert.equal(secrets.decrypt(a), 'ghp_supersecret'); const t = a.slice(0, -3) + (a.endsWith('AAA') ? 'BBB' : 'AAA'); assert.throws(() => secrets.decrypt(t));
});

test('GitHub collector: baselines silently, then raises a leaked-secret and a deploy key; token is stored encrypted and never returned', async () => {
  h.fresh(); reset(); state.gh.alerts = [{ number: 1, secret_type: 'old_token', created_at: new Date().toISOString() }];
  const col = await C().create({ platform: 'github', name: 'acme web', token: 'ghp_testtoken123', config: { repo: 'acme/web' } }, 'admin');
  assert.ok(!JSON.stringify(col).includes('ghp_testtoken123')); const raw = db.get().prepare('select token_enc from collectors').get().token_enc; assert.ok(!raw.includes('ghp_testtoken123'));
  const before = evs().recent?.(500).length ?? 0;
  assert.equal((await C().runOne(col.id)).events, 0, 'no re-alert for what already existed');
  state.gh.alerts.push({ number: 2, secret_type: 'aws_access_key_id', secret_type_display_name: 'AWS key', created_at: new Date().toISOString() }); state.gh.keys = [{ id: 9, title: 'ci', read_only: false }];
  const r = await C().runOne(col.id); assert.equal(r.status, 'ok'); assert.equal(r.events, 2);
  assert.equal((await C().runOne(col.id)).events, 0, 'dedupes on the next poll');
  assert.equal(C().list().find((x) => x.id === col.id).totalEvents, 2); assert.ok(h.audit.recent(500).some((e) => e.action === 'COLLECTOR_ADDED'));
});

test('Heroku collector turns router lines and config-var changes into events', async () => {
  h.fresh(); reset(); const t0 = Date.now() - 5000, ts = (o) => new Date(t0 + o).toISOString();
  state.heroku = `${ts(0)} heroku[router]: at=info method=GET path="/old" host=a.com fwd="203.0.113.5" status=200\n`;
  const col = await C().create({ platform: 'heroku', token: 'hrku-tok-12345', config: { app: 'shop' } }, 'admin');
  const lines = []; for (let i = 0; i < 8; i++) lines.push(`${ts(1000 + i)} heroku[router]: at=info method=GET path="/.env${i}" host=a.com fwd="203.0.113.77" status=404`);
  lines.push(`${ts(2000)} heroku[api]: Set STRIPE_KEY config vars by user eve@x.com`); state.heroku += lines.join('\n');
  const r = await C().runOne(col.id); assert.equal(r.status, 'ok'); assert.ok(r.events >= 9, 'got ' + r.events);
  await h.until(() => [...h.cmd.incidents.values()].some((i) => /probe|scan|R-WEB/i.test(JSON.stringify(i.alerts))), 8000);
});

test('Vercel, Netlify and Render collectors map deploys and service events', async () => {
  h.fresh(); reset();
  const v = await C().create({ platform: 'vercel', token: 'vercel-token-1', config: {} }, 'admin');
  const n = await C().create({ platform: 'netlify', token: 'netlify-token-1', config: { siteId: 's1' } }, 'admin');
  const rd = await C().create({ platform: 'render', token: 'render-token-1', config: {} }, 'admin');
  state.vercel = [{ uid: 'dpl_1', name: 'shop', state: 'READY', target: 'production', created: Date.now(), creator: { username: 'dev' } }, { uid: 'dpl_2', name: 'shop', state: 'BUILDING' }];
  state.netlify = [{ id: 'nd1', site_id: 's1', name: 'blog', state: 'error', created_at: new Date().toISOString(), context: 'production' }];
  state.render.events = [{ event: { id: 'evd-1', timestamp: new Date().toISOString(), type: 'deploy_ended', details: { status: 'failed' } } }];
  state.render.logs = [{ timestamp: new Date().toISOString(), message: 'GET /x', labels: [{ name: 'type', value: 'request' }, { name: 'clientIP', value: '198.51.100.8' }, { name: 'path', value: '/wp-login.php' }, { name: 'statusCode', value: '404' }, { name: 'method', value: 'GET' }] }];
  assert.equal((await C().runOne(v.id)).events, 1); assert.equal((await C().runOne(n.id)).events, 1); const r = await C().runOne(rd.id); assert.equal(r.status, 'ok'); assert.ok(r.events >= 2, 'render events+logs: ' + r.events);
});

test('bad token is rejected at connect time; a revoked token flips the collector to auth_failed; invalid config is refused', async () => {
  h.fresh(); reset(); state.authFail = true;
  await assert.rejects(() => C().create({ platform: 'netlify', token: 'wrong-token-1', config: { siteId: 's1' } }, 'admin'), /rejected the token/);
  state.authFail = false; const col = await C().create({ platform: 'netlify', token: 'netlify-token-2', config: { siteId: 's1' } }, 'admin');
  state.authFail = true; const r = await C().runOne(col.id); assert.equal(r.status, 'auth_failed'); assert.equal(C().list().find((x) => x.id === col.id).status, 'auth_failed');
  await assert.rejects(() => C().create({ platform: 'github', token: 'abcdefghij', config: { repo: 'no-slash' } }, 'a'), /invalid/); await assert.rejects(() => C().create({ platform: 'ftp', token: 'abcdefghij', config: {} }, 'a'), /unsupported/);
  C().remove(col.id, 'admin'); assert.ok(!C().list().some((x) => x.id === col.id));
});
