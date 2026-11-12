'use strict';
process.env.PHOENIX_DB = ':memory:'; process.env.PHOENIX_QUIET = '1'; process.env.PHOENIX_GENERATOR = 'off'; process.env.PHOENIX_VERIFY_ALLOW_PRIVATE = '1'; process.env.PHOENIX_CHANNEL_ALLOW_ANY_URL = '1'; process.env.PHOENIX_PUBLIC_URL = 'https://phoenix.example';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const app = require('../server/index');
const rz = require('../server/resilience');
const channels = require('../server/channels');
const h = require('./helpers');

let base, mock, mbase, sess; const sent = { tg: [], slack: [], discord: [], mail: [], follow: [] }; let tgUpdates = [];
const SUPA = 'abcdref123';
async function api(method, path, body) { const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', cookie: sess.cookie, 'x-csrf-token': sess.csrf }, body: body ? JSON.stringify(body) : undefined }); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; } return { status: r.status, body: j }; }
const TOKEN = '123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
test.before(async () => {
  mock = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), p = u.pathname, j = (o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    let body = ''; req.on('data', (d) => (body += d)); req.on('end', () => {
      if (p === `/tg/bot${TOKEN}/getMe`) return j({ ok: true, result: { username: 'phoenix_bot' } });
      if (p === `/tg/bot${TOKEN}/getUpdates`) { const r = tgUpdates; tgUpdates = []; return j({ ok: true, result: r }); }
      if (p === `/tg/bot${TOKEN}/sendMessage`) { sent.tg.push(JSON.parse(body)); return j({ ok: true }); }
      if (p === '/slackhook') { sent.slack.push(JSON.parse(body)); return j({}); }
      if (p === '/discordhook') { sent.discord.push(JSON.parse(body)); return j({}); }
      if (p === '/resend/emails') { sent.mail.push({ auth: req.headers.authorization, ...JSON.parse(body) }); return j({ id: 'm1' }); }
      if (p === '/slackresp') { sent.follow.push(JSON.parse(body)); return j({}); }
      // provider mocks for posture
      if (p === '/supabase/projects') return j([{ id: SUPA, name: 'shop-db' }]);
      if (p === `/supabase/projects/${SUPA}/database/query`) return j([{ tablename: 'users', rowsecurity: false }, { tablename: 'posts', rowsecurity: true }]);
      if (p === `/supabase/projects/${SUPA}/database/backups`) return j({ backups: [{ inserted_at: new Date().toISOString(), status: 'COMPLETED' }] });
      if (p === '/render/services') return j([{ service: { id: 'srv-api', name: 'api', repo: 'https://github.com/acme/web', serviceDetails: { url: 'https://api.example.com' } } }]);
      if (p === '/render/services/srv-api/env-vars') return j([{ envVar: { key: 'STRIPE_SECRET_KEY', value: 'x' } }, { envVar: { key: 'NEXT_PUBLIC_SERVICE_ROLE_KEY', value: 'y' } }, { envVar: { key: 'NEXT_PUBLIC_SUPABASE_ANON_KEY', value: 'z' } }]);
      if (/^\/gh\/repos\/acme\/web\/(secret-scanning\/alerts|keys|events)$/.test(p)) return j([]);
      if (p === '/gh/repos/acme/web/branches/main/protection') return j({ message: 'Branch not protected' }, 404);
      if (p === '/gh/repos/acme/web') return j({ full_name: 'acme/web', html_url: 'https://github.com/acme/web', default_branch: 'main', security_and_analysis: { secret_scanning: { status: 'disabled' } } });
      j({ message: 'nope' }, 404);
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r)); mbase = 'http://127.0.0.1:' + mock.address().port;
  Object.assign(process.env, { PHOENIX_API_TELEGRAM: mbase + '/tg', PHOENIX_API_RESEND: mbase + '/resend', PHOENIX_API_SUPABASE: mbase + '/supabase', PHOENIX_API_RENDER: mbase + '/render', PHOENIX_API_GITHUB: mbase + '/gh' });
  app.boot(); await new Promise((r) => app.server.listen(0, '127.0.0.1', r)); base = 'http://127.0.0.1:' + app.server.address().port;
  const r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'phoenix-demo' }) }); const j = await r.json();
  sess = { cookie: r.headers.get('set-cookie').split(';')[0], csrf: j.csrf };
  for (const [platform, config] of [['supabase', {}], ['render', {}], ['github', { repo: 'acme/web' }]]) await api('POST', '/api/collectors', { platform, token: 'tok_' + platform + '_12345', config });
  await api('POST', '/api/resilience/discover');
});
test.after(() => { app.server.close(); mock.close(); channels.stop(); require('../server/core/persist').stop(); });

test('posture scan finds browser-exposed secrets, Supabase tables without RLS, unprotected branch, and gives fixes', async () => {
  const r = (await api('POST', '/api/resilience/posture')).body; const by = (c) => r.findings.filter((f) => f.check === c);
  assert.equal(by('client_exposed_secret').length, 1, 'only the private-looking NEXT_PUBLIC variable, not the anon key'); assert.match(by('client_exposed_secret')[0].where, /SERVICE_ROLE/);
  assert.deepEqual(by('supabase_rls_off').map((f) => f.where), ['shop-db.public.users']); assert.match(by('supabase_rls_off')[0].fix, /enable row level security/);
  assert.equal(by('github_no_branch_protection').length, 1); assert.equal(by('github_secret_scanning_off').length, 1);
  assert.ok(r.score < 60 && r.counts.critical === 2, JSON.stringify(r.counts)); assert.equal((await api('GET', '/api/resilience/posture')).body.latest.id, r.id);
});

test('leaked-secret auto-response: GitHub secret-scan alert → matching variables, blast radius and a plan preview', async () => {
  const inc = { id: 'INC-LEAK', alerts: [{ rule: 'R-PLATFORM-SECRET-EXPOSED', evidenceSummary: 'github: secret scanning: Stripe API Key by octocat on acme/web', affected: { resources: ['acme/web'] } }] };
  const l = await rz.leak.forIncident(inc, 'test'); assert.equal(l.provider, 'Stripe'); assert.deepEqual(l.matched.map((m) => m.name), ['api:STRIPE_SECRET_KEY']); assert.deepEqual(l.blast.deployments, ['api']);
  assert.ok(l.planId); const plan = (await api('GET', '/api/resilience/plans/' + l.planId)).body; assert.equal(plan.status, 'preview', 'still needs admin approval');
  const none = await rz.leak.forIncident({ alerts: [{ rule: 'R-PLATFORM-SECRET-EXPOSED', evidenceSummary: 'github: secret scanning: Mailgun Key on acme/web', affected: { resources: ['acme/web'] } }] }, 'test'); assert.equal(none.matched.length, 0); assert.match(none.summary, /No matching variable/);
});

test('plain-language briefing restates the incident record', async () => {
  const inc = await h.run('credential-compromise'); const b = (await api('GET', `/api/incidents/${inc.id}/briefing`)).body;
  assert.ok(b.headline && b.whyItMatters && Array.isArray(b.doNow) && b.doNow.length <= 3); assert.ok(b.whatHappened.length >= 1);
  assert.match(rz.brief.text(b), /What to do now/);
});

test('game day: scores every scenario, keeps history, and alerts when readiness drops', async () => {
  await api('POST', '/api/resilience/checks', { name: 'API health', type: 'http', config: { url: mbase + '/render/services' } });
  const g1 = (await api('POST', '/api/resilience/gameday')).body; assert.ok(g1.score > 0 && g1.items.length >= 3); assert.equal(g1.alert, false);
  let dropped = null; rz.gameday.onDrop((r) => { dropped = r; });
  for (const c of (await api('GET', '/api/resilience/checks')).body.checks) await api('POST', `/api/resilience/checks/${c.id}/remove`, {}); // lose the ability to prove recovery
  const g2 = (await api('POST', '/api/resilience/gameday')).body; assert.ok(g2.delta < 0 && g2.alert && dropped, `delta ${g2.delta}`);
  assert.equal((await api('GET', '/api/resilience/gameday')).body.history.length, 2);
});

test('channels: config validation, secrets never returned, alerts-only email refuses pairing', async () => {
  assert.equal((await api('POST', '/api/channels', { kind: 'telegram', config: { botToken: 'nope' } })).status, 400);
  assert.equal((await api('POST', '/api/channels', { kind: 'slack', config: { signingSecret: 'abcdefgh', webhookUrl: 'https://evil.example/x' } })).status, 201, 'ANY_URL is on for tests');
  delete process.env.PHOENIX_CHANNEL_ALLOW_ANY_URL; assert.equal((await api('POST', '/api/channels', { kind: 'slack', config: { signingSecret: 'abcdefgh', webhookUrl: 'https://evil.example/x' } })).status, 400, 'webhook host is restricted'); process.env.PHOENIX_CHANNEL_ALLOW_ANY_URL = '1';
  assert.equal((await api('POST', '/api/channels', { kind: 'discord', config: { publicKey: 'zz' } })).status, 400);
  const em = (await api('POST', '/api/channels', { kind: 'email', config: { apiKey: 're_secretkey123', from: 'phoenix@acme.com', to: 'me@acme.com' } })).body; assert.ok(!JSON.stringify(em).includes('re_secretkey123'));
  assert.equal((await api('POST', `/api/channels/${em.id}/pair`)).status, 400);
  for (const c of (await api('GET', '/api/channels')).body.channels) if (c.kind === 'slack') await api('POST', `/api/channels/${c.id}/remove`);
  assert.equal((await api('POST', `/api/channels/${em.id}/test`)).status, 200); assert.equal(sent.mail[0].auth, 'Bearer re_secretkey123'); await api('POST', `/api/channels/${em.id}/remove`);
});

test('Telegram: pair with a one-time code, run commands, unknown users refused, approvals refused with an app link', async () => {
  const ch = (await api('POST', '/api/channels', { kind: 'telegram', name: 'Ops bot', config: { botToken: TOKEN } })).body; assert.equal(ch.status, 'pending');
  const say = async (id, text) => { sent.tg.length = 0; tgUpdates = [{ update_id: Math.floor(Math.random() * 1e6) + 10, message: { text, from: { id }, chat: { id, type: 'private' } } }]; await channels.tick(); return sent.tg[0]?.text || ''; };
  assert.match(await say(777, 'status'), /don't know you[\s\S]*777/);
  const { code } = (await api('POST', `/api/channels/${ch.id}/pair`)).body; assert.match(await say(777, 'link WRONG123'), /wrong or expired/);
  assert.match(await say(777, 'link ' + code), /Paired/); assert.match(await say(888, 'link ' + code), /wrong or expired/, 'one-time code');
  assert.match(await say(777, 'status'), /./); assert.ok(!(await say(777, 'what is ransomware')).includes('**'), 'markdown stripped for Telegram');
  // operations the AI may do work from chat
  assert.match(await say(777, 'block 203.0.113.77'), /203\.0\.113\.77/);
  assert.ok(require('../server/agents/commander').manualList().some((a) => a.target?.ip === '203.0.113.77' && a.requestedBy === 'telegram:777'), 'attributed to the Telegram user');
  assert.match(await say(777, "what's blocked"), /203\.0\.113\.77/); assert.match(await say(777, 'unblock 203.0.113.77'), /./);
  // human-decision operations are refused and point to the app
  for (const t of ['allow', 'approve all', 'rotate all keys', 'set mode to full', 'protect bob', 'trust sam', 'done', 'discover']) { const r = await say(777, t); assert.match(r, /needs a human decision/, t); assert.match(r, /phoenix\.example\/#\/response/); }
  assert.equal(require('../server/core/autonomy').getMode(), 'balanced', 'mode unchanged');
  // role is capped: viewer channel cannot block
  await api('POST', `/api/channels/${ch.id}/settings`, { role: 'viewer' }); assert.match(await say(777, 'block 203.0.113.78'), /requires|analyst|permission|not allowed/i); await api('POST', `/api/channels/${ch.id}/settings`, { role: 'analyst' });
  // alerts go to paired chats, honouring the minimum severity
  sent.tg.length = 0; await channels.broadcast('🚨 test', 'body', { severity: 'low' }); assert.equal(sent.tg.length, 0); await channels.broadcast('🚨 test', 'body', { severity: 'critical' }); assert.equal(sent.tg.at(-1).chat_id, '777');
  await api('POST', `/api/channels/${ch.id}/remove`);
});

test('Slack: slash commands need a valid signature; replies are ephemeral and formatted', async () => {
  const SECRET = 'slacksecret123'; const ch = (await api('POST', '/api/channels', { kind: 'slack', config: { signingSecret: SECRET, webhookUrl: mbase + '/slackhook' } })).body; await api('POST', `/api/channels/${ch.id}/allow`, { user: 'U1' });
  const post = async (text, user = 'U1', { ts = Math.floor(Date.now() / 1000), bad = false } = {}) => { const body = new URLSearchParams({ command: '/phoenix', text, user_id: user, response_url: mbase + '/slackresp' }).toString(); const sig = 'v0=' + crypto.createHmac('sha256', bad ? 'wrong' : SECRET).update(`v0:${ts}:${body}`).digest('hex'); return fetch(base + `/api/channels/slack/${ch.id}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-slack-request-timestamp': String(ts), 'x-slack-signature': sig }, body }); };
  assert.equal((await post('status', 'U1', { bad: true })).status, 401); assert.equal((await post('status', 'U1', { ts: 1000 })).status, 401, 'stale timestamp = replay');
  const ok = await post('what is ransomware'); assert.equal(ok.status, 200); const j = await ok.json(); assert.equal(j.response_type, 'ephemeral'); assert.ok(!j.text.includes('**'));
  assert.match((await (await post('status', 'U9')).json()).text, /don't know you/); assert.match((await (await post('allow')).json()).text, /human decision/);
  sent.slack.length = 0; await channels.broadcast('Alert', 'hello', { severity: 'critical' }); assert.match(sent.slack[0].text, /\*Alert\*/);
  await api('POST', `/api/channels/${ch.id}/remove`);
});

test('Discord: Ed25519-verified interactions (ping, command), bad signature rejected', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const ch = (await api('POST', '/api/channels', { kind: 'discord', config: { publicKey: pub, webhookUrl: mbase + '/discordhook' } })).body; await api('POST', `/api/channels/${ch.id}/allow`, { user: 'D1' });
  const post = async (obj, { bad = false } = {}) => { const raw = JSON.stringify(obj), ts = String(Date.now()); const sig = crypto.sign(null, Buffer.from(ts + raw), privateKey).toString('hex'); return fetch(base + `/api/channels/discord/${ch.id}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-signature-timestamp': ts, 'x-signature-ed25519': bad ? '00'.repeat(64) : sig }, body: raw }); };
  assert.deepEqual(await (await post({ type: 1 })).json(), { type: 1 }); assert.equal((await post({ type: 1 }, { bad: true })).status, 401);
  const r = await (await post({ type: 2, member: { user: { id: 'D1' } }, data: { name: 'phoenix', options: [{ name: 'text', value: 'what is ransomware' }] } })).json(); assert.equal(r.type, 4); assert.equal(r.data.flags, 64); assert.match(r.data.content, /ransomware/i);
  const r2 = await (await post({ type: 2, member: { user: { id: 'D1' } }, data: { name: 'phoenix', options: [{ name: 'text', value: 'rotate all keys' }] } })).json(); assert.match(r2.data.content, /human decision/);
  await api('POST', `/api/channels/${ch.id}/remove`);
});

test('incident alerts reach channels with a plain-language briefing and an app link, once per incident', async () => {
  const ch = (await api('POST', '/api/channels', { kind: 'slack', config: { signingSecret: 'abcdefgh', webhookUrl: mbase + '/slackhook' }, minSeverity: 'medium' })).body; sent.slack.length = 0; channels.reset();
  const inc = await h.run('ransomware'); await h.until(() => sent.slack.some((m) => /Needs your OK|Resolved|CRITICAL|HIGH/i.test(m.text)), 15000);
  const texts = sent.slack.map((m) => m.text); assert.ok(texts.some((t) => /What to do now/.test(t) && t.includes('phoenix.example/#/incidents/' + inc.id)), texts.join('\n---\n').slice(0, 400));
  assert.equal(texts.filter((t) => t.includes('What to do now')).length, 1, 'one alert per incident, not one per update');
  await api('POST', `/api/channels/${ch.id}/remove`);
});
