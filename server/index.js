'use strict';
try { process.loadEnvFile(require('path').join(__dirname, '..', '.env')); } catch { /* .env is optional */ }
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const cfg = require('./core/config');
const log = require('./core/log');
const bus = require('./core/bus');
const audit = require('./core/audit');
const events = require('./core/events');
const gen = require('./core/generator');
const auth = require('./core/auth');
const ws = require('./core/ws');
const persist = require('./core/persist');
const dbm = require('./core/db');
const registry = require('./core/registry');
const suppress = require('./core/suppressions');
const sim = require('./sim/enterprise');
const cmd = require('./agents/commander');
const guardian = require('./agents/guardian');
const oracle = require('./agents/oracle');
const kb = require('./agents/kb');
const scen = require('./scenarios');
const notifications = require('./integrations/notifications');
const ticketing = require('./integrations/ticketing');
const supa = require('./integrations/supabase');
const connectors = require('./connectors');
const normalize = require('./ingest/normalize');
const catalog = require('./ingest/catalog');
const autonomy = require('./core/autonomy');
const collectors = require('./collectors');
const rz = require('./resilience');
const channels = require('./channels');
const assistant = require('./agents/assistant');

const PUB = path.join(__dirname, '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.woff': 'font/woff', '.png': 'image/png', '.txt': 'text/plain; charset=utf-8' };
const STARTED = Date.now();
const COOKIE = 'phx_session';
let booted = false;

const learning = () => Object.entries(sim.env.users).filter(([, u]) => u._auto).map(([n, u]) => ({ user: n, learning: !u.homeGeo, logins: u._clean || 0, homeGeo: u.homeGeo || null }));

// ---- views ----
const summary = (i) => ({ id: i.id, title: i.title, state: i.state, status: i.status, priority: i.priority, severity: i.severity, riskScore: i.riskScore, createdAt: i.createdAt, workflow: i.workflow, analyst: i.analyst, alerts: i.alerts.length, actions: i.containment.length, pendingApprovals: i.containment.filter((a) => a.status === 'pending_approval').length, origin: i.origin, scenarioId: i.scenarioId, degraded: i.degraded, ticket: i.ticket && { id: i.ticket.id, system: i.ticket.system, confirmed: i.ticket.confirmed }, tasks: { done: i.recovery.tasks.filter((t) => t.status === 'done').length, total: i.recovery.tasks.length }, categories: [...new Set(i.alerts.map((a) => a.category))], mitre: [...new Set(i.alerts.flatMap((a) => a.mitre.map((m) => m.id)))] });
const integrations = () => relabel({
  'Threat intel (VirusTotal)': oracle.hasVT() ? 'configured (live)' : 'simulator (local sample DB)', 'Slack': notifications.status().slack, 'Teams': notifications.status().teams, 'Email': notifications.status().email, 'SMS': notifications.status().sms,
  'Ticketing (Jira)': ticketing.status(), 'Identity (Supabase Auth)': guardian.supaOn() ? 'configured (user map required)' : 'not used', 'Database (Supabase)': supa.status(), 'LLM narrative': process.env.ANTHROPIC_API_KEY ? 'configured' : 'off (deterministic analysis only)', 'Cloud audit logs': 'CloudTrail JSON via /api/ingest/cloudtrail', 'Log ingest API': auth.listKeys().some((k) => !k.disabled) ? 'enabled (' + auth.listKeys().filter((k) => !k.disabled).length + ' active key(s))' : 'no ingest keys yet (create one in Settings)',
});
const relabel = (o) => (cfg.isProd ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, /^simulator|^off|local memory|not configured/i.test(String(v)) ? 'not configured' : v])) : o);
function analytics() {
  const ev = events.all(), now = Date.now(), B = 30e3, N = 20;
  const series = Array.from({ length: N }, (_, i) => ({ t: now - (N - 1 - i) * B, generated: 0, scenario: 0, ingested: 0 }));
  for (const e of ev) { const age = now - new Date(e.ts).getTime(); if (age < 0 || age >= N * B) continue; series[N - 1 - Math.floor(age / B)][e.origin]++; }
  const bySource = {}; ev.slice(-2000).forEach((e) => (bySource[e.source] = (bySource[e.source] || 0) + 1));
  const L = [...cmd.incidents.values()]; const mitre = {}, cats = {}, rules = {};
  L.forEach((i) => { i.alerts.forEach((a) => { cats[a.category] = (cats[a.category] || 0) + 1; rules[a.rule] = (rules[a.rule] || 0) + 1; }); (i.investigation?.techniques || []).forEach((t) => { mitre[t.id] = mitre[t.id] || { name: t.name, n: 0, status: t.status }; mitre[t.id].n++; if (t.status === 'evidence-supported') mitre[t.id].status = t.status; }); });
  return { series, bySource, mitre, cats, rules, contain: L.filter((i) => i.timing.containedAt).map((i) => ({ id: i.id, sec: Math.round((new Date(i.timing.containedAt) - new Date(i.timing.detectedAt)) / 1000) })) };
}
const state = () => ({ metrics: { ...cmd.metrics(), eventsToday: events.all().length, wsClients: ws.count() }, incidents: [...cmd.incidents.values()].map(summary).reverse(), agents: cmd.agentStats, messages: cmd.messages.slice(-60), scenarios: scen.list(), integrations: integrations(), mode: cfg.mode, connectors: connectors.status(), manual: cmd.manualList().slice(-50), autonomy: { ...autonomy.status(), protected: autonomy.listProtected() }, settings: { ...cmd.settings, autoContain: guardian.config.autoContain, generator: gen.running, mode: cfg.mode, allowScenarios: cfg.allowScenarios, connectorDryRun: cfg.connectorDryRun }, suppressions: suppress.list(), learning: learning(), approvals: cmd.pendingFor().map((p) => ({ incidentId: p.incidentId, action: p.action })), events: events.recent(80), assets: sim.snapshot(), analytics: analytics(), ops: ops() });
function ops() { return { outbox: sim.env.outbox.slice(-15).reverse(), tickets: sim.env.tickets.slice(-15).reverse() }; }

// ---- realtime fan-out ----
bus.on('event', (e) => { ws.broadcast('event', e); supa.upsert('mirror_security_events', e.id, e); });
bus.on('alert', (a) => ws.broadcast('alert', a));
bus.on('incident', (i) => { ws.broadcast('incident', summary(i)); supa.upsert('mirror_incidents', i.id, summary(i)); });
bus.on('agent_msg', (m) => ws.broadcast('agent_msg', m));
bus.on('agents', (a) => ws.broadcast('agents', a));
bus.on('approval', (a) => ws.broadcast('approval', { incidentId: a.incidentId, action: a.action }));
bus.on('audit', (a) => { ws.broadcast('audit', a); supa.upsert('mirror_audit_logs', 'a' + a.seq, a); });
bus.on('scenario', (s) => ws.broadcast('scenario', s));
bus.on('notification', (n) => ws.broadcast('notification', n));
setInterval(() => ws.broadcast('metrics', { ...cmd.metrics(), eventsToday: events.all().length, assets: sim.snapshot(), analytics: analytics(), ops: ops() }), 2000).unref();

// ---- http helpers ----
const json = (res, code, obj) => { if (!res.headersSent) res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); };
const zlib = require('zlib');
// Returns { body, raw }. Accepts JSON, NDJSON (Vercel/Cloudflare), gzip (Cloudflare Logpush), and text (syslog, Heroku Logplex, access logs).
const readBody = (req, max = 2e6, rawOnly = false) => new Promise((ok, bad) => {
  const chunks = []; let n = 0; const ct = req.headers['content-type'] || '';
  req.on('data', (c) => { n += c.length; if (n > max) { req.destroy(); return bad(Object.assign(new Error('body too large'), { code: 413 })); } chunks.push(c); });
  req.on('end', () => {
    let buf = Buffer.concat(chunks);
    if (/gzip/i.test(req.headers['content-encoding'] || '')) { try { buf = zlib.gunzipSync(buf, { maxOutputLength: max * 4 }); } catch { return bad(Object.assign(new Error('invalid gzip body'), { code: 400 })); } }
    const raw = buf.toString('utf8'); const sig = Buffer.concat(chunks).toString('utf8');
    if (rawOnly) return ok({ body: {}, raw: sig });
    if (!raw.trim()) return ok({ body: {}, raw: sig });
    if (/^text\/plain|logplex/i.test(ct)) return ok({ body: { lines: raw }, raw: sig });
    try { return ok({ body: JSON.parse(raw), raw: sig }); } catch { /* maybe NDJSON */ }
    const ls = raw.split(/\r?\n/).filter((l) => l.trim()); const arr = [];
    for (const l of ls) { try { arr.push(JSON.parse(l)); } catch { return bad(Object.assign(new Error('invalid JSON'), { code: 400 })); } }
    ok({ body: arr, raw: sig });
  });
  req.on('error', bad);
});
const parseCookies = (h) => Object.fromEntries(String(h || '').split(/;\s*/).filter(Boolean).map((p) => { const i = p.indexOf('='); return [p.slice(0, i), decodeURIComponent(p.slice(i + 1))]; }));
const clientIp = (req) => (cfg.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;
const bearer = (req) => (req.headers.authorization || '').replace(/^Bearer /, '') || null;
const sessionOf = (req, url) => { const c = parseCookies(req.headers.cookie)[COOKIE]; if (c) { const u = auth.verify(c); if (u) return { ...u, viaCookie: true, token: c }; } const t = bearer(req) || url.searchParams.get('token'); const u = t && auth.verify(t); return u ? { ...u, viaCookie: false, token: t } : null; };
const setCookie = (res, token, maxAgeSec) => res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${cfg.cookieSecure ? '; Secure' : ''}`);
const isStr = (v, max = 500) => typeof v === 'string' && v.length > 0 && v.length <= max;
const ID = /^[A-Za-z0-9._:@-]{1,64}$/;
const prodOff = (what) => [403, { error: `${what} is disabled in production mode` }];
const hits = new Map();
function limited(key, max, winMs = 60e3) { const t = Date.now(), a = (hits.get(key) || []).filter((x) => t - x < winMs); a.push(t); hits.set(key, a); if (hits.size > 5000) for (const [k, v] of hits) if (!v.some((x) => t - x < winMs)) hits.delete(k); return a.length > max; }

const routes = []; // [method, regex, minRole|null, handler, opts]
const R = (m, p, role, h, opts = {}) => routes.push([m, new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), role, h, opts]);

// ---- health / ops (no auth; they reveal nothing sensitive) ----
R('GET', '/healthz', null, async () => [200, { ok: true, uptimeSec: Math.round((Date.now() - STARTED) / 1000), mode: cfg.mode }]);
R('GET', '/readyz', null, async () => { try { dbm.get().prepare('select 1').get(); const v = audit.verify(); return v.ok ? [200, { ready: true }] : [503, { ready: false, reason: 'audit chain verification failed', brokenAt: v.brokenAt }]; } catch (e) { return [503, { ready: false, reason: e.message }]; } });
R('GET', '/metrics', null, async (c) => {
  const tok = bearer(c.req); if (!(cfg.metricsToken && tok === cfg.metricsToken) && !c.user) return [401, { error: 'metrics token or login required' }];
  const m = cmd.metrics(); const L = (n, h, v) => `# HELP ${n} ${h}\n# TYPE ${n} gauge\n${n} ${v}\n`;
  return [200, L('phoenix_uptime_seconds', 'Process uptime', Math.round((Date.now() - STARTED) / 1000)) + L('phoenix_incidents_total', 'Incidents known', m.totalIncidents) + L('phoenix_incidents_active', 'Open incidents', m.activeIncidents) + L('phoenix_incidents_critical', 'Open critical incidents', m.criticalThreats) + L('phoenix_pending_approvals', 'Actions awaiting approval', m.pendingApprovals) + L('phoenix_events_buffered', 'Events held in memory', events.all().length) + L('phoenix_ws_clients', 'WebSocket clients', ws.count()) + L('phoenix_audit_chain_ok', 'Audit hash chain verifies (1/0)', audit.verify().ok ? 1 : 0) + L('phoenix_audit_entries', 'Audit log entries', audit.recent(1e9).length), 'text/plain; version=0.0.4'];
}, { open: true });

// ---- auth ----
R('GET', '/api/auth/status', null, async () => [200, { mode: cfg.mode, setupRequired: auth.needsSetup(), setupTokenRequired: !!cfg.setupToken, demo: auth.demoCreds(), password: auth.demoCreds() ? auth.DEMO_PW : undefined, requireAdminTotp: cfg.requireAdminTotp }]);
const sessionReply = (c, r) => { setCookie(c.res, r.token, cfg.sessionHours * 3600); return [200, { user: r.user, role: r.role, csrf: r.csrf, token: r.token, mustChange: r.mustChange, totpEnrolRequired: r.totpEnrolRequired, mode: cfg.mode }]; };
R('POST', '/api/auth/setup', null, async (c) => { if (!auth.needsSetup() && auth.count() > 0) return [409, { error: 'setup already completed' }]; if (limited('setup:' + c.ip, 10)) return [429, { error: 'too many attempts' }]; try { auth.firstAdmin(c.body, c.ip); } catch (e) { return [400, { error: e.message }]; } const r = auth.login({ username: c.body.username, password: c.body.password }, { ip: c.ip, ua: c.req.headers['user-agent'] }); return r.error ? [400, { error: r.error }] : sessionReply(c, r); });
R('POST', '/api/auth/login', null, async (c) => { const r = auth.login(c.body || {}, { ip: c.ip, ua: c.req.headers['user-agent'] }); if (r.error) return [r.code || 401, { error: r.error, totpRequired: !!r.totpRequired }]; return sessionReply(c, r); });
R('POST', '/api/auth/logout', 'viewer', async (c) => { auth.logout(c.user.token); setCookie(c.res, '', 0); audit.log(c.user.sub, 'LOGOUT', {}); return [200, { ok: true }]; }, { enrol: true });
R('GET', '/api/auth/me', 'viewer', async (c) => [200, { user: c.user.sub, role: c.user.role, csrf: c.user.csrf, mustChange: c.user.mustChange, totpEnrolRequired: c.user.enrolOnly, mode: cfg.mode, totp: !!auth.listUsers().find((u) => u.username === c.user.sub)?.totp }], { enrol: true });
R('POST', '/api/auth/password', 'viewer', async (c) => { try { auth.changePassword(c.user.sub, c.body.current, c.body.next); } catch (e) { return [400, { error: e.message }]; } return [200, { ok: true, note: 'all sessions were revoked; sign in again' }]; }, { enrol: true });
R('POST', '/api/auth/totp/begin', 'viewer', async (c) => [200, auth.totpBegin(c.user.sub)], { enrol: true });
R('POST', '/api/auth/totp/confirm', 'viewer', async (c) => { try { auth.totpConfirm(c.user.sub, c.body.code); } catch (e) { return [400, { error: e.message }]; } return [200, { ok: true }]; }, { enrol: true });

// ---- user / key / suppression / asset administration ----
R('GET', '/api/users', 'admin', async () => [200, auth.listUsers()]);
R('POST', '/api/users', 'admin', async (c) => { try { return [201, auth.createUser({ username: c.body.username, password: c.body.password, role: c.body.role || 'analyst', mustChange: !!c.body.mustChange }, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/users/:name/update', 'admin', async (c) => { try { return [200, auth.updateUser(c.p.name, { role: c.body.role, disabled: c.body.disabled, password: c.body.password }, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/users/:name/delete', 'admin', async (c) => { try { if (c.p.name === c.user.sub) return [400, { error: 'you cannot delete yourself' }]; auth.deleteUser(c.p.name, c.user.sub); return [200, { ok: true }]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/users/:name/totp-reset', 'admin', async (c) => { auth.totpDisable(c.p.name, c.user.sub); auth.revokeAll(c.p.name); return [200, { ok: true }]; });
R('GET', '/api/keys', 'admin', async () => [200, { keys: auth.listKeys(), formats: auth.FORMATS }]);
R('POST', '/api/keys', 'admin', async (c) => { try { return [201, auth.createKey({ name: c.body.name, format: c.body.format, signingSecret: c.body.signingSecret, verifyToken: c.body.verifyToken }, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/keys/:id/revoke', 'admin', async (c) => { try { auth.revokeKey(c.p.id, c.user.sub); return [200, { ok: true }]; } catch (e) { return [404, { error: e.message }]; } });
R('GET', '/api/collectors', 'admin', async () => [200, { collectors: collectors.list(), catalog: collectors.catalog() }]);
R('POST', '/api/keys/rotate-all', 'admin', async (c) => { try { return [200, { keys: auth.rotateAll(c.user.sub) }]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/keys/:id/rotate', 'admin', async (c) => { try { return [200, auth.rotateKey(c.p.id, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/collectors/:id/token', 'admin', async (c) => { try { return [200, collectors.updateToken(c.p.id, c.body.token, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/collectors', 'admin', async (c) => { try { return [201, await collectors.create(c.body, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/collectors/:id/run', 'admin', async (c) => { const r = await collectors.runOne(c.p.id); return r ? [200, r] : [404, { error: 'not found or already running' }]; });
R('POST', '/api/collectors/:id/enable', 'admin', async (c) => { collectors.setEnabled(c.p.id, !!c.body.enabled, c.user.sub); return [200, { ok: true }]; });
R('POST', '/api/collectors/:id/remove', 'admin', async (c) => { collectors.remove(c.p.id, c.user.sub); return [200, { ok: true }]; });
R('POST', '/api/collectors/:id/write', 'admin', async (c) => { try { return [200, collectors.setWrite(c.p.id, !!c.body.enabled, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
// ---- Application resilience: map, blast radius, rehearsal, safe recovery, verification, memory ----
const RZ = (fn) => async (c) => { try { return await fn(c); } catch (e) { return [400, { error: e.message }]; } };
R('GET', '/api/resilience/graph', 'viewer', async () => [200, { nodes: rz.graph.nodes(), edges: rz.graph.edges(), summary: rz.graph.summary() }]);
R('POST', '/api/resilience/discover', 'admin', RZ(async (c) => [200, await rz.discover.discoverAll(c.user.sub)]));
R('POST', '/api/resilience/graph', 'admin', RZ(async (c) => [200, rz.graph.addDeclared(c.body, c.user.sub)]));
R('POST', '/api/resilience/graph/remove', 'admin', RZ(async (c) => [200, { ok: rz.graph.removeNode(String(c.body.id || ''), c.user.sub) }]));
R('POST', '/api/resilience/blast', 'analyst', RZ(async (c) => { const hit = rz.graph.find(c.body.target); if (!hit.length) return [404, { error: 'no matching node' }]; return [200, rz.blast.compute([hit[0].id])]; }));
R('GET', '/api/resilience/scenarios', 'viewer', async () => [200, { scenarios: rz.rehearse.SCENARIOS, suggested: rz.rehearse.suggest(), history: rz.rehearse.history() }]);
R('POST', '/api/resilience/rehearse', 'analyst', RZ(async (c) => [200, await rz.rehearse.run({ scenario: c.body.scenario || 'credential', target: c.body.target, by: c.user.sub })]));
R('GET', '/api/resilience/rehearsals/:id', 'viewer', async (c) => { const r = rz.rehearse.get(c.p.id); return r ? [200, r] : [404, { error: 'not found' }]; });
R('POST', '/api/resilience/backup', 'admin', RZ(async (c) => [200, rz.rehearse.attestBackup(String(c.body.node || ''), c.body.note, c.user.sub)]));
R('GET', '/api/resilience/plans', 'viewer', async () => [200, { plans: rz.recover.list() }]);
R('POST', '/api/resilience/plans', 'analyst', RZ(async (c) => [201, await rz.recover.create(c.body, c.user.sub)]));
R('GET', '/api/resilience/plans/:id', 'viewer', async (c) => { const r = rz.recover.get(c.p.id); return r ? [200, r] : [404, { error: 'not found' }]; });
R('POST', '/api/resilience/plans/:id/approve', 'admin', RZ(async (c) => [200, rz.recover.approve(c.p.id, c.user.sub)]));
R('POST', '/api/resilience/plans/:id/reject', 'admin', RZ(async (c) => [200, rz.recover.reject(c.p.id, c.user.sub)]));
R('POST', '/api/resilience/plans/:id/execute', 'admin', RZ(async (c) => [200, await rz.recover.execute(c.p.id, c.user.sub)]));
R('POST', '/api/resilience/plans/:id/steps/:sid', 'admin', RZ(async (c) => [200, await rz.recover.markStep(c.p.id, c.p.sid, c.user.sub, c.body.state || 'done')]));
R('POST', '/api/resilience/plans/:id/steps/:sid/undo', 'admin', RZ(async (c) => [200, await rz.recover.undoStep(c.p.id, c.p.sid, c.user.sub)]));
R('GET', '/api/resilience/checks', 'viewer', async () => [200, { checks: rz.verify.list(), types: rz.verify.TYPES, reports: rz.verify.reports(10) }]);
R('POST', '/api/resilience/checks', 'admin', RZ(async (c) => [201, rz.verify.add(c.body, c.user.sub)]));
R('POST', '/api/resilience/checks/:id/remove', 'admin', RZ(async (c) => [200, { ok: rz.verify.remove(c.p.id, c.user.sub) }]));
R('POST', '/api/resilience/verify', 'analyst', RZ(async (c) => [200, await rz.verify.run({ ref: c.body.ref || null, by: c.user.sub })]));
// ---- Chat channels (Telegram / Slack / Discord / email) ----
R('GET', '/api/channels', 'admin', async () => [200, { channels: channels.list(), catalog: channels.catalog(), publicUrl: process.env.PHOENIX_PUBLIC_URL || null }]);
R('POST', '/api/channels', 'admin', RZ(async (c) => [201, await channels.create(c.body, c.user.sub)]));
R('POST', '/api/channels/:id/remove', 'admin', RZ(async (c) => [200, { ok: channels.remove(c.p.id, c.user.sub) }]));
R('POST', '/api/channels/:id/enable', 'admin', RZ(async (c) => { channels.setEnabled(c.p.id, !!c.body.enabled, c.user.sub); return [200, { ok: true }]; }));
R('POST', '/api/channels/:id/settings', 'admin', RZ(async (c) => { channels.update(c.p.id, c.body, c.user.sub); return [200, { ok: true }]; }));
R('POST', '/api/channels/:id/pair', 'admin', RZ(async (c) => [200, channels.pairCode(c.p.id, c.user.sub)]));
R('POST', '/api/channels/:id/allow', 'admin', RZ(async (c) => [200, { allow: channels.allow(c.p.id, c.body.user, c.body.on !== false, c.user.sub) }]));
R('POST', '/api/channels/:id/test', 'admin', RZ(async (c) => [200, await channels.test(c.p.id, c.user.sub)]));
R('POST', '/api/channels/slack/:id', null, async (c) => channels.slackInbound(c.p.id, c.req.headers, c.raw), { raw: true, body: 1e5 });
R('POST', '/api/channels/discord/:id', null, async (c) => channels.discordInbound(c.p.id, c.req.headers, c.raw), { raw: true, body: 1e5 });
// ---- posture, game day, briefings ----
R('POST', '/api/resilience/posture', 'analyst', RZ(async (c) => [200, await rz.posture.run(c.user.sub)]));
R('GET', '/api/resilience/posture', 'viewer', async () => [200, { latest: rz.posture.latest(), history: rz.posture.history() }]);
R('POST', '/api/resilience/gameday', 'analyst', RZ(async (c) => [200, await rz.gameday.run(c.user.sub)]));
R('GET', '/api/resilience/gameday', 'viewer', async () => [200, { latest: rz.gameday.latest(), history: rz.gameday.history(), everyHours: +process.env.PHOENIX_GAMEDAY_HOURS || 0 }]);
R('GET', '/api/incidents/:id/briefing', 'viewer', async (c) => { const i = cmd.incidents.get(c.p.id); return i ? [200, rz.brief.briefing(i)] : [404, { error: 'not found' }]; });
R('GET', '/api/resilience/memory', 'viewer', async () => [200, { incidents: rz.memory.all().map((m) => ({ incidentId: m.incidentId, title: m.title, severity: m.severity, at: m.at, verified: !!m.verification?.passed, sha256: m.sha256, signals: m.signature.length })) }]);
R('GET', '/api/resilience/memory/:id', 'viewer', async (c) => { const b = rz.memory.bundle(c.p.id); return b ? [200, b] : [404, { error: 'not found' }]; });
R('GET', '/api/incidents/:id/similar', 'viewer', async (c) => { const inc = cmd.incidents.get(c.p.id); return [200, { similar: inc ? rz.memory.similar(inc) : [] }]; });
R('POST', '/api/manual', 'analyst', async (c) => { try { return [200, await cmd.manualAction(String(c.body.type), c.body.target || {}, c.user.sub, String(c.body.reason || '').slice(0, 200))]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/chat', 'viewer', async (c) => { try { return [200, await assistant.handle({ sub: c.user.sub, role: c.user.role }, c.body.message)]; } catch (e) { return [200, { reply: '⚠️ ' + e.message }]; } });
R('GET', '/api/autonomy', 'viewer', async () => [200, { ...autonomy.status(), protected: autonomy.listProtected() }]);
R('POST', '/api/autonomy', 'admin', async (c) => { try { autonomy.setMode(String(c.body.mode), c.user.sub); guardian.config.autoContain = autonomy.getMode() !== 'watch'; return [200, { ...autonomy.status(), protected: autonomy.listProtected() }]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/protected', 'admin', async (c) => { try { return [201, autonomy.protect({ kind: c.body.kind, value: c.body.value, reason: c.body.reason, hours: +c.body.hours || null }, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/protected/:id/remove', 'admin', async (c) => { autonomy.unprotect(c.p.id, c.user.sub); return [200, { ok: true }]; });
R('GET', '/api/containments', 'viewer', async () => [200, { containments: cmd.containments() }]);
R('POST', '/api/actions/:id/undo', 'analyst', async (c) => { try { if (c.body.trust && !auth.allowed(c.user.role, 'admin')) return [403, { error: 'only an admin can mark an entity as trusted' }]; return [200, await cmd.undoAction(c.p.id, c.user.sub, { trust: !!c.body.trust, reason: String(c.body.reason || '').slice(0, 200) })]; } catch (e) { return [400, { error: e.message }]; } });
R('GET', '/api/suppressions', 'viewer', async () => [200, suppress.list()]);
R('POST', '/api/suppressions', 'admin', async (c) => { try { return [201, suppress.add(c.body, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/suppressions/:id/remove', 'admin', async (c) => { try { suppress.remove(c.p.id, c.user.sub); return [200, { ok: true }]; } catch (e) { return [404, { error: e.message }]; } });
R('GET', '/api/assets', 'viewer', async () => [200, sim.snapshot()]);
R('POST', '/api/assets/backups', 'admin', async (c) => { try { return [201, registry.addBackup(c.body.host, c.body)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/assets/:kind/:name', 'admin', async (c) => { try { registry.upsertAsset(c.p.kind, c.p.name, c.body || {}); return [200, { ok: true }]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/admin/backup', 'admin', async (c) => { const f = dbm.backup(); audit.log(c.user.sub, 'BACKUP_CREATED', { file: path.basename(f) }); return [200, { file: f }]; });

// ---- data ----
R('GET', '/api/state', 'viewer', async (c) => [200, { ...state(), me: { user: c.user.sub, role: c.user.role } }]);
R('GET', '/api/incidents/:id', 'viewer', async (c) => { const i = cmd.incidents.get(c.p.id); return i ? [200, { ...i, audit: audit.forIncident(i.id) }] : [404, { error: 'not found' }]; });
R('GET', '/api/incidents/:id/report.md', 'viewer', async (c) => { const i = cmd.incidents.get(c.p.id); if (!i?.report) return [404, { error: 'report not ready' }]; audit.log(c.user.sub, 'REPORT_EXPORTED', { format: 'md' }, i.id); return [200, i.report, 'text/markdown; charset=utf-8', `attachment; filename="${i.id}-report.md"`]; });
R('GET', '/api/incidents/:id/report.json', 'viewer', async (c) => { const i = cmd.incidents.get(c.p.id); if (!i) return [404, { error: 'not found' }]; audit.log(c.user.sub, 'REPORT_EXPORTED', { format: 'json' }, i.id); return [200, JSON.stringify({ ...i, audit: audit.forIncident(i.id) }, null, 2), 'application/json', `attachment; filename="${i.id}-evidence-bundle.json"`]; });
R('POST', '/api/incidents/:id/notes', 'analyst', async (c) => { if (!isStr(c.body.text, 2000)) return [400, { error: 'text required' }]; return [200, summary(cmd.addNote(c.p.id, c.user.sub, c.body.text))]; });
R('POST', '/api/incidents/:id/assign', 'analyst', async (c) => { if (!isStr(c.body.analyst, 80)) return [400, { error: 'analyst required' }]; return [200, summary(cmd.assign(c.p.id, c.user.sub, c.body.analyst))]; });
R('POST', '/api/incidents/:id/status', 'analyst', async (c) => { try { return [200, summary(cmd.setStatus(c.p.id, c.user.sub, c.body.status))]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/incidents/:id/verify', 'analyst', async (c) => { const i = await cmd.rerunVerification(c.p.id, c.user.sub); return [200, summary(i)]; });
R('POST', '/api/incidents/:id/tasks/complete-all', 'analyst', async (c) => { const i = cmd.incidents.get(c.p.id); if (!i) return [404, { error: 'not found' }]; for (let n = 0; n < 20; n++) { const t = i.recovery.tasks.find((x) => x.status === 'pending' && x.owner === 'human' && (x.dependsOn || []).every((d) => i.recovery.tasks.find((y) => y.id === d)?.status === 'done' || i.recovery.tasks.find((y) => y.id === d)?.status === 'skipped')); if (!t) break; await cmd.completeTask(i.id, t.id, c.user.sub); } return [200, summary(i)]; });
R('POST', '/api/incidents/:id/tasks/:tid/check', 'analyst', async (c) => { try { return [200, await cmd.checkTask(c.p.id, c.p.tid, c.user.sub)]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/incidents/:id/tasks/:tid/skip', 'analyst', async (c) => { try { await cmd.skipTask(c.p.id, c.p.tid, c.user.sub); return [200, { ok: true }]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/incidents/:id/tasks/:tid/complete', 'analyst', async (c) => { try { await cmd.completeTask(c.p.id, c.p.tid, c.user.sub); return [200, { ok: true }]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/actions/:id/approve', 'admin', async (c) => { try { return [200, await cmd.decide(c.p.id, true, c.user.sub, String(c.body.comment || '').slice(0, 500))]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/actions/:id/reject', 'admin', async (c) => { try { return [200, await cmd.decide(c.p.id, false, c.user.sub, String(c.body.comment || '').slice(0, 500))]; } catch (e) { return [400, { error: e.message }]; } });
R('POST', '/api/scenarios/:id/launch', 'analyst', async (c) => { if (!cfg.allowScenarios) return prodOff('Attack simulation'); if (!scen.list().some((s) => s.id === c.p.id || c.p.id === 'signature')) return [404, { error: 'unknown scenario' }]; if (typeof c.body.autopilot === 'boolean') cmd.setAutopilot(c.body.autopilot); audit.log(c.user.sub, 'SCENARIO_REQUESTED', { id: c.p.id, autopilot: cmd.settings.autopilot }); scen.launch(c.p.id, { speed: 1, reset: !!c.body.reset }).catch((e) => audit.log('SCENARIO', 'SCENARIO_ERROR', { error: e.message })); return [202, { launched: c.p.id }]; });
R('POST', '/api/settings', 'admin', async (c) => { const b = c.body; if (typeof b.autopilot === 'boolean') { if (cfg.isProd && b.autopilot) return prodOff('Autopilot'); cmd.setAutopilot(b.autopilot); } if (Number.isFinite(b.paceMs)) cmd.settings.paceMs = Math.min(5000, Math.max(0, b.paceMs)); if (typeof b.autoContain === 'boolean') guardian.config.autoContain = b.autoContain; if (typeof b.generator === 'boolean') { if (cfg.isProd && b.generator) return prodOff('The synthetic generator'); b.generator ? gen.start() : gen.stop(); } if (Number.isFinite(b.approvalTimeoutMin)) cmd.settings.approvalTimeoutMin = Math.min(1440, Math.max(0, b.approvalTimeoutMin)); audit.log(c.user.sub, 'SETTINGS_CHANGED', b); try { dbm.kvSet('settings', { paceMs: cmd.settings.paceMs, autopilot: cmd.settings.autopilot, autoContain: guardian.config.autoContain, approvalTimeoutMin: cmd.settings.approvalTimeoutMin }); } catch { /* best effort */ } return [200, state().settings]; });
R('POST', '/api/reset', 'admin', async (c) => { if (cfg.isProd) return prodOff('Environment reset'); cmd.reset(); events.reset(); sim.reset(); audit.log(c.user.sub, 'ENVIRONMENT_RESET', {}); ws.broadcast('reset', {}); return [200, { ok: true }]; });
R('POST', '/api/guardian/execute', 'admin', async (c) => { // policy tester: proves restricted actions can never run
  if (cfg.isProd) return prodOff('The policy tester');
  const { type, target } = c.body; if (!isStr(type, 40) || typeof target !== 'object') return [400, { error: 'type,target required' }];
  const action = { id: 'manual-' + Date.now(), type, target, tier: guardian.classify(type, target).tier, status: 'planned', description: 'manual policy test' };
  const r = await guardian.execute(action, { incidentId: null, approvedBy: c.body.approve ? c.user.sub : null }); return [200, { policy: guardian.classify(type, target), result: r }]; });
R('GET', '/api/events', 'viewer', async (c) => [200, events.recent(Math.min(500, +c.url.searchParams.get('limit') || 100))]);
R('GET', '/api/audit', 'viewer', async (c) => [200, audit.recent(Math.min(1000, +c.url.searchParams.get('limit') || 300))]);
R('GET', '/api/audit/verify', 'viewer', async () => [200, audit.verify()]);
R('GET', '/api/kb', 'viewer', async (c) => [200, c.url.searchParams.get('q') ? kb.search(c.url.searchParams.get('q'), 5) : kb.DOCS]);
R('POST', '/api/intel/lookup', 'analyst', async (c) => { const { type, value } = c.body; if (!['ip', 'domain', 'hash'].includes(type) || !isStr(value, 200)) return [400, { error: 'type (ip|domain|hash) and value required' }]; return [200, await oracle.lookup(type, value)]; });
R('POST', '/api/incidents/:id/resume', 'admin', async (c) => { try { return [200, summary(await cmd.resume(c.p.id, c.user.sub))]; } catch (e) { return [400, { error: e.message }]; } });
// ---- ingestion ----
// A source authenticates with a per-source key sent as header x-api-key, as the HTTP Basic *password* (Heroku drains),
// or inside the URL (/api/hook/<key>) for platforms that cannot set headers. Platforms that sign webhooks (Vercel, GitHub,
// Netlify) are additionally verified when the key has a signing secret.
const hmac = (alg, secret, data) => require('crypto').createHmac(alg, secret).update(data).digest();
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && require('crypto').timingSafeEqual(x, y); };
const b64u = (b) => Buffer.from(b).toString('base64url');
function checkSignature(format, secret, req, raw) {
  const H = (n) => req.headers[n] || '';
  if (format === 'vercel' || format === 'vercel-webhook') return safeEq(hmac('sha1', secret, raw).toString('hex'), H('x-vercel-signature'));
  if (format === 'github') return safeEq('sha256=' + hmac('sha256', secret, raw).toString('hex'), H('x-hub-signature-256'));
  if (format === 'netlify') { // JWS (HS256): payload has iss=netlify and sha256 = hex SHA-256 of the raw body
    const [h, p, sg] = String(H('x-webhook-signature')).split('.'); if (!sg) return false;
    if (!safeEq(b64u(hmac('sha256', secret, h + '.' + p)), sg)) return false;
    try { const hd = JSON.parse(Buffer.from(h, 'base64url')), pl = JSON.parse(Buffer.from(p, 'base64url')); return hd.alg === 'HS256' && pl.iss === 'netlify' && safeEq(pl.sha256, require('crypto').createHash('sha256').update(raw).digest('hex')); } catch { return false; }
  }
  return true; // no signature scheme for this format; the key itself authenticates
}
const keyFrom = (c) => {
  const h = c.req.headers; if (h['x-api-key']) return auth.verifyKey(String(h['x-api-key']));
  const b = /^Basic (.+)$/i.exec(h.authorization || ''); if (b) { const pw = Buffer.from(b[1], 'base64').toString().split(':').slice(1).join(':'); return auth.verifyKey(pw); }
  if (c.p.key) return auth.verifyKey(c.p.key);
  return null;
};
async function ingestRoute(c, format) {
  const key = keyFrom(c);
  if (!key && !(c.user && auth.allowed(c.user.role, 'admin'))) return [401, { error: 'valid ingest key required (x-api-key header, Basic password, or /api/hook/<key>)' }];
  if (key && c.p.key === undefined && format && key.format !== format && key.format !== 'generic') return [403, { error: `this key is bound to format "${key.format}"` }];
  format = (c.p.key !== undefined ? key?.format : format) || key?.format || 'generic';
  if (key?.meta?.verifyToken) c.res.setHeader('x-vercel-verify', key.meta.verifyToken); // Vercel endpoint-verification handshake
  if (limited('ingest:' + (key?.id || c.user?.sub), 600)) return [429, { error: 'rate limit: 600 requests/minute per source' }];
  if (c.req.method === 'GET' || !c.raw || !String(c.raw).trim()) return [200, { ok: true, format, note: 'endpoint reachable; send events with POST' }];
  if (key?.meta?.signingSecret && !checkSignature(format, key.meta.signingSecret, c.req, c.raw)) { audit.log('INGEST:' + key.name, 'INGEST_SIGNATURE_REJECTED', { format }); return [401, { error: 'signature verification failed' }]; }
  let body = c.body; if (format === 'github') body = { ...(Array.isArray(body) ? {} : body), __event: c.req.headers['x-github-event'] };
  try { const r = normalize.ingest(format, body); if (key) auth.touchKey(key.id, r.accepted); audit.log(key ? 'INGEST:' + key.name : c.user.sub, 'EVENTS_INGESTED', { format, accepted: r.accepted, duplicates: r.duplicates, ignored: r.ignored, rejected: r.rejected.length }); return [r.accepted || !r.rejected.length ? 200 : 422, r]; } catch (e) { return [400, { error: e.message }]; }
}
R('POST', '/api/ingest', null, (c) => ingestRoute(c, null), { body: 5e6 });
R('POST', '/api/ingest/:format', null, (c) => (normalize.FORMATS.includes(c.p.format) ? ingestRoute(c, c.p.format) : [404, { error: 'unknown format; use ' + normalize.FORMATS.join(', ') }]), { body: 5e6 });
R('POST', '/api/hook/:key', null, (c) => ingestRoute(c, null), { body: 5e6 });
R('GET', '/api/hook/:key', null, (c) => ingestRoute(c, null));
R('GET', '/api/platforms', 'admin', async () => [200, catalog.PLATFORMS]);
R('POST', '/api/keys/:id/test', 'admin', async (c) => { const k = auth.keyById(c.p.id); if (!k || k.disabled) return [404, { error: 'no such active key' }]; const r = normalize.ingest('generic', { events: [{ source: 'system', type: 'connection_test', outcome: 'success', details: { key: k.name, note: 'Connection test sent from the dashboard' } }] }); auth.touchKey(k.id, r.accepted); audit.log(c.user.sub, 'INGEST_KEY_TESTED', { id: k.id }); return [200, { ok: true }]; });

async function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin'); res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (cfg.cookieSecure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  const ip = clientIp(req);
  if (url.pathname.startsWith('/api/') || ['/healthz', '/readyz', '/metrics'].includes(url.pathname)) {
    try {
      if (limited('api:' + ip, 900)) return json(res, 429, { error: 'rate limit exceeded' });
      for (const [m, re, role, h, opts] of routes) {
        const mt = req.method === m && re.exec(url.pathname); if (!mt) continue;
        const user = sessionOf(req, url);
        if (role && !user) return json(res, 401, { error: 'authentication required' });
        if (user && user.enrolOnly && !opts.enrol && role) return json(res, 403, { error: 'two-factor enrolment required: set up an authenticator app first', totpEnrolRequired: true });
        if (user && user.mustChange && !opts.enrol && role) return json(res, 403, { error: 'password change required', mustChange: true });
        if (role && !auth.allowed(user.role, role)) { audit.log(user.sub, 'FORBIDDEN', { path: url.pathname, need: role }); return json(res, 403, { error: `requires ${role} role` }); }
        if (user?.viaCookie && req.method !== 'GET' && req.headers['x-csrf-token'] !== user.csrf) return json(res, 403, { error: 'CSRF token missing or invalid' });
        const rb = req.method === 'POST' ? await readBody(req, opts.body, opts.raw) : { body: {}, raw: '' }; const body = rb.body;
        for (const v of Object.values(mt.groups || {})) if (!ID.test(v)) return json(res, 400, { error: 'invalid id' });
        const out = await h({ req, res, url, ip, p: mt.groups || {}, body, raw: rb.raw, user }); const [code, payload, type, disp] = out;
        if (type) { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', ...(disp ? { 'content-disposition': disp } : {}) }); return res.end(payload); }
        return json(res, code, payload);
      }
      return json(res, 404, { error: 'not found' });
    } catch (e) { if (e.code === 413 || e.code === 400) return json(res, e.code, { error: e.message }); log.error('request failed', { path: url.pathname, error: e.message }); return json(res, 500, { error: 'internal error' }); }
  }
  if (url.pathname === '/classic') { res.writeHead(301, { location: '/classic/' }); return res.end(); }
  let f = path.join(PUB, url.pathname === '/' ? 'index.html' : path.normalize(url.pathname).replace(/^(\.\.[/\\])+/, ''));
  if (f.startsWith(PUB) && fs.existsSync(f) && fs.statSync(f).isDirectory()) f = path.join(f, 'index.html');
  if (!f.startsWith(PUB) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end('not found'); }
  res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream', 'cache-control': 'no-store' }); fs.createReadStream(f).pipe(res);
}
const server = cfg.tls.cert ? https.createServer({ cert: fs.readFileSync(cfg.tls.cert), key: fs.readFileSync(cfg.tls.key) }, handler) : http.createServer(handler);
server.requestTimeout = 30000; server.headersTimeout = 15000;
const originOk = (req) => { const o = req.headers.origin; if (!o) return true; try { const h = new URL(o).host; return h === req.headers.host || (process.env.PHOENIX_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean).includes(o); } catch { return false; } };
server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://x'); if (url.pathname !== '/ws') return socket.destroy();
  if (!originOk(req)) { socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return socket.destroy(); }
  const s = ws.accept(req, socket, () => { const u = sessionOf(req, url); return u && !u.enrolOnly ? u : null; }); if (s) ws.send(s, 'hello', { user: s.user.sub, role: s.user.role });
});

// ---- lifecycle ----
function boot({ quiet } = {}) {
  if (booted) return; booted = true;
  const v = cfg.validate(); v.warn.forEach((w) => log.warn(w)); if (v.fatal.length) { v.fatal.forEach((f) => log.error(f)); throw new Error('Invalid configuration: ' + v.fatal.join(' | ')); }
  const p = persist.start(cfg.dbPath, { retentionDays: cfg.retentionDays });
  if (!p.audit.ok) log.error('audit chain failed verification at startup', { brokenAt: p.audit.brokenAt });
  if (auth.seedDemo()) log.warn('demo users created (admin/analyst/viewer). Change their passwords or run in production mode.');
  autonomy.load(); cmd.loadManual(); channels.wire(); channels.start(); rz.gameday.start(); rz.gameday.onDrop((r, bad) => channels.broadcast('📉 Recovery readiness dropped', `Game-day score is now ${r.score}/100${r.delta != null ? ' (' + r.delta + ')' : ''}.${bad.length ? ' Newly NOT READY: ' + bad.map((b) => b.label).join(', ') + '.' : ''}`, { severity: 'high', key: r.id })); collectors.start(+process.env.PHOENIX_POLL_SEC * 1000 || 15000); guardian.config.autoContain = autonomy.getMode() !== 'watch' && guardian.config.autoContain !== false; log.info('autonomy', { mode: autonomy.getMode() });
  cmd.attach(); cmd.settings.autopilot = !cfg.isProd && cmd.settings.autopilot !== false;
  audit.log('SYSTEM', 'PHOENIX_STARTED', { mode: cfg.mode, restored: p.restored, interrupted: p.interrupted, connectors: connectors.status() });
  if (cfg.generator) gen.start(900);
  setInterval(() => { cmd.sweepExpired().catch((e) => log.error('self-recovery failed', { error: e.message })); cmd.sweepChecks().catch(() => {}); }, +process.env.PHOENIX_SWEEP_SEC * 1000 || 60e3).unref();
  setInterval(() => { try { auth.purgeSessions(); ws.prune((u) => !!auth.verify(u.token)); } catch { /* best effort */ } }, 60e3).unref();
  const bk = +process.env.PHOENIX_BACKUP_EVERY_HOURS; if (bk > 0) setInterval(() => { try { const f = dbm.backup(); log.info('scheduled backup', { file: f }); } catch (e) { log.error('backup failed', { error: e.message }); } }, bk * 3600e3).unref();
  log.info('phoenix ready', { mode: cfg.mode, restoredIncidents: p.restored, interrupted: p.interrupted });
}
let closing = false;
function shutdown(sig) {
  if (closing) return; closing = true; log.info('shutting down', { signal: sig });
  try { audit.log('SYSTEM', 'PHOENIX_STOPPING', { signal: sig }); } catch { /* ignore */ }
  collectors.stop(); channels.stop(); rz.gameday.stop(); server.close(); ws.closeAll(); setTimeout(() => process.exit(1), 8000).unref();
  try { persist.stop(); } catch (e) { log.error('flush failed', { error: e.message }); }
  process.exit(0);
}
process.on('uncaughtException', (e) => { try { audit.log('SYSTEM', 'UNCAUGHT_EXCEPTION_CONTAINED', { error: e.message }); } catch { /* ignore */ } log.error('uncaught exception', { error: e.stack }); });
process.on('unhandledRejection', (e) => { try { audit.log('SYSTEM', 'UNHANDLED_REJECTION_CONTAINED', { error: String(e) }); } catch { /* ignore */ } log.error('unhandled rejection', { error: String(e) }); });

if (require.main === module) {
  try { boot(); } catch (e) { console.error('\n  Cannot start: ' + e.message + '\n'); process.exit(1); }
  process.on('SIGTERM', () => shutdown('SIGTERM')); process.on('SIGINT', () => shutdown('SIGINT'));
  server.listen(cfg.port, cfg.host, () => {
    const proto = cfg.tls.cert ? 'https' : 'http';
    console.log(`\n  PHOENIX X — Detect. Investigate. Contain. Recover.   [${cfg.mode.toUpperCase()} MODE]\n  Dashboard: ${proto}://${cfg.host === '0.0.0.0' ? 'localhost' : cfg.host}:${cfg.port}`);
    if (auth.needsSetup()) console.log('  FIRST RUN: open the dashboard to create the administrator account.' + (cfg.setupToken ? ' (setup token required: PHOENIX_SETUP_TOKEN)' : ''));
    else if (auth.demoCreds()) console.log(`  Demo logins: admin / analyst / viewer — password "${auth.DEMO_PW}"`);
    if (cfg.isProd) console.log('  Production: no simulated data. Send logs to /api/ingest. Containment connectors: ' + JSON.stringify(connectors.status()) + '\n');
  });
}
module.exports = { server, state, boot, shutdown };
