'use strict';
// CHAT CHANNELS: talk to PHOENIX X from Telegram, Slack and Discord, and get alerts by Telegram, Slack, Discord and email.
// Safety model:
//  * Only people you PAIR (one-time code sent from your own chat) or allow-list can give commands. Everyone else is refused.
//  * Commands run with at most the "analyst" role and only the operations the AI itself may do (block/unblock, status, explain, rehearse, verify…).
//  * Anything that needs a human decision (Allow/Disallow, key rotation, mode changes, recovery steps, trust lists) is refused here and
//    points to the app, so approvals always happen in the authenticated dashboard.
//  * Inbound Slack requests are verified by HMAC signing secret, Discord by Ed25519 public key. Telegram uses long polling (no public URL).
//  * Tokens and secrets are stored AES-256-GCM encrypted and never returned by the API.
const crypto = require('crypto');
const db = require('../core/db'); const audit = require('../core/audit'); const secrets = require('../core/secrets'); const bus = require('../core/bus'); const log = require('../core/log');

const SEV = { low: 1, medium: 2, high: 3, critical: 4 };
const API = { telegram: () => process.env.PHOENIX_API_TELEGRAM || 'https://api.telegram.org', discord: () => process.env.PHOENIX_API_DISCORD || 'https://discord.com/api/v10', resend: () => process.env.PHOENIX_API_RESEND || 'https://api.resend.com' };
const anyUrl = () => process.env.PHOENIX_CHANNEL_ALLOW_ANY_URL === '1';
const hookOk = (u, hosts) => { try { const x = new URL(u); return anyUrl() || (x.protocol === 'https:' && hosts.some((h) => x.hostname === h || x.hostname.endsWith('.' + h))); } catch { return false; } };
const SPEC = {
  telegram: { label: 'Telegram', inbound: true, fields: [{ k: 'botToken', label: 'Bot token (from @BotFather)', secret: true }], help: 'Create a bot with @BotFather, paste the token, then press "Pair" and send the code to your bot.' },
  slack: { label: 'Slack', inbound: true, fields: [{ k: 'signingSecret', label: 'Signing secret (Basic Information)', secret: true }, { k: 'webhookUrl', label: 'Incoming webhook URL (for alerts)', secret: true, optional: true }], help: 'Create a Slack app, add a slash command /phoenix pointing to the request URL shown after saving, and (optional) an incoming webhook for alerts.' },
  discord: { label: 'Discord', inbound: true, fields: [{ k: 'publicKey', label: 'Application public key', secret: false }, { k: 'webhookUrl', label: 'Channel webhook URL (for alerts)', secret: true, optional: true }], help: 'Create a Discord application with a /phoenix command (one text option), set the Interactions Endpoint URL shown after saving, and (optional) add a channel webhook for alerts.' },
  email: { label: 'Email (alerts only)', inbound: false, fields: [{ k: 'apiKey', label: 'Resend API key', secret: true }, { k: 'from', label: 'From address', secret: false }, { k: 'to', label: 'Send alerts to (comma separated)', secret: false }], help: 'Alerts only. Commands are not accepted by email because sender addresses can be forged.' },
};
const catalog = () => Object.fromEntries(Object.entries(SPEC).map(([k, v]) => [k, { label: v.label, inbound: v.inbound, fields: v.fields, help: v.help }]));
const publicUrl = () => (process.env.PHOENIX_PUBLIC_URL || '').replace(/\/$/, '');
const inboundUrl = (c) => ({ slack: `/api/channels/slack/${c.id}`, discord: `/api/channels/discord/${c.id}` }[c.kind] || null);

async function http(url, { method = 'GET', body, headers = {}, form } = {}) {
  const r = await fetch(url, { method, signal: AbortSignal.timeout(10000), headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch { /* text */ }
  if (!r.ok) throw Object.assign(new Error(`HTTP ${r.status} from ${new URL(url).host}`), { status: r.status, body: t.slice(0, 120) });
  return j ?? t;
}
const row = (r) => r && ({ id: r.id, kind: r.kind, name: r.name, role: r.role, minSeverity: r.min_severity, enabled: !!r.enabled, allow: JSON.parse(r.allow || '[]'), status: r.last_status || 'pending', error: r.last_error, lastRun: r.last_run, createdBy: r.created_by, createdAt: r.created_at, pairing: !!(r.pair_code && Date.parse(r.pair_exp) > Date.now()) });
const raw = (id) => db.get().prepare('select * from channels where id=?').get(id);
const cfgOf = (r) => JSON.parse(secrets.decrypt(r.config_enc));
const list = () => db.get().prepare('select * from channels order by created_at').all().map((r) => ({ ...row(r), inboundUrl: inboundUrl(r), spec: SPEC[r.kind]?.label, hasWebhook: !!cfgOf(r).webhookUrl }));
function clean(kind, c = {}) {
  const spec = SPEC[kind]; if (!spec) throw new Error('kind must be telegram, slack, discord or email'); const o = {};
  for (const f of spec.fields) { const v = String(c[f.k] ?? '').trim(); if (!v) { if (f.optional) continue; throw new Error(f.label + ' is required'); } o[f.k] = v; }
  if (kind === 'telegram' && !/^\d{5,}:[\w-]{20,}$/.test(o.botToken)) throw new Error('that does not look like a Telegram bot token');
  if (kind === 'slack') { if (o.signingSecret.length < 8) throw new Error('signing secret looks too short'); if (o.webhookUrl && !hookOk(o.webhookUrl, ['slack.com'])) throw new Error('webhook must be a https://hooks.slack.com URL'); }
  if (kind === 'discord') { if (!/^[0-9a-f]{64}$/i.test(o.publicKey)) throw new Error('public key must be 64 hex characters'); if (o.webhookUrl && !hookOk(o.webhookUrl, ['discord.com', 'discordapp.com'])) throw new Error('webhook must be a https://discord.com URL'); }
  if (kind === 'email') { o.to = o.to.split(',').map((s) => s.trim()).filter(Boolean); if (!o.to.length || o.to.some((e) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) || !/^[^<>]*<?[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+>?$/.test(o.from)) throw new Error('check the email addresses'); }
  return o;
}
async function create({ kind, name, config, role = 'analyst', minSeverity = 'high' }, by) {
  const cfg = clean(kind, config); if (!SEV[minSeverity]) throw new Error('minSeverity must be low, medium, high or critical'); role = role === 'viewer' ? 'viewer' : 'analyst'; // never above analyst
  let cursor = {}; if (kind === 'telegram') { const me = await http(`${API.telegram()}/bot${cfg.botToken}/getMe`).catch((e) => { throw new Error('Telegram rejected the token (' + e.message + ')'); }); cfg.botName = me.result?.username; const up = await http(`${API.telegram()}/bot${cfg.botToken}/getUpdates?offset=-1&timeout=0`).catch(() => ({ result: [] })); cursor = { offset: ((up.result || []).at(-1)?.update_id || 0) + 1 }; }
  const id = 'ch-' + crypto.randomBytes(4).toString('hex');
  db.get().prepare('insert into channels(id,kind,name,config_enc,role,min_severity,cursor,created_by,created_at) values(?,?,?,?,?,?,?,?,?)').run(id, kind, String(name || SPEC[kind].label).slice(0, 60), secrets.encrypt(JSON.stringify(cfg)), role, minSeverity, JSON.stringify(cursor), by, new Date().toISOString());
  audit.log(by, 'CHANNEL_ADDED', { id, kind, role, minSeverity }); return list().find((c) => c.id === id);
}
function remove(id, by) { const r = db.get().prepare('delete from channels where id=?').run(id); audit.log(by, 'CHANNEL_REMOVED', { id }); return r.changes > 0; }
function setEnabled(id, on, by) { db.get().prepare('update channels set enabled=? where id=?').run(on ? 1 : 0, id); audit.log(by, on ? 'CHANNEL_ENABLED' : 'CHANNEL_PAUSED', { id }); }
function update(id, { role, minSeverity }, by) { const r = raw(id); if (!r) throw new Error('not found'); if (minSeverity && !SEV[minSeverity]) throw new Error('bad severity'); db.get().prepare('update channels set role=?, min_severity=? where id=?').run(role ? (role === 'viewer' ? 'viewer' : 'analyst') : r.role, minSeverity || r.min_severity, id); audit.log(by, 'CHANNEL_UPDATED', { id, role, minSeverity }); }
function pairCode(id, by) { const r = raw(id); if (!r) throw new Error('not found'); if (!SPEC[r.kind].inbound) throw new Error('this channel is alerts-only'); const code = crypto.randomBytes(4).toString('hex').toUpperCase(); db.get().prepare('update channels set pair_code=?, pair_exp=? where id=?').run(crypto.createHash('sha256').update(code).digest('hex'), new Date(Date.now() + 15 * 60e3).toISOString(), id); audit.log(by, 'CHANNEL_PAIR_CODE', { id }); return { code, expiresInMinutes: 15, say: `link ${code}` }; }
function allow(id, extId, on, by) { const r = raw(id); if (!r) throw new Error('not found'); const a = new Set(JSON.parse(r.allow || '[]')); on ? a.add(String(extId)) : a.delete(String(extId)); db.get().prepare('update channels set allow=? where id=?').run(JSON.stringify([...a]), id); audit.log(by, on ? 'CHANNEL_USER_ALLOWED' : 'CHANNEL_USER_REMOVED', { id, user: String(extId) }); return [...a]; }

// ---------- formatting ----------
const fmt = {
  telegram: (t) => String(t).replace(/\*\*/g, '').slice(0, 3900), email: (t) => String(t).replace(/\*\*/g, ''),
  slack: (t) => String(t).replace(/\*\*(.+?)\*\*/g, '*$1*').slice(0, 3000), discord: (t) => String(t).slice(0, 1900),
};
const withChoices = (o) => String(o.reply || '') + (o.choices?.length ? '\n\n' + o.choices.map((c) => '• ' + (c.send || c.label)).join('\n') : '');

// ---------- inbound: one entry point for every platform ----------
const rate = new Map();
function limited(k) { const now = Date.now(), a = (rate.get(k) || []).filter((t) => now - t < 60000); a.push(now); rate.set(k, a); return a.length > 20; }
async function command(chId, extId, text) {
  const r = raw(chId); if (!r || !r.enabled) return { reply: 'This channel is paused.' };
  extId = String(extId); text = String(text || '').trim().replace(/^\/(?:phoenix|start|p)\b@?\w*\s*/i, '').trim();
  const allowed = JSON.parse(r.allow || '[]'), m = /^(?:\/?link|pair)\s+([0-9A-Za-z]{6,12})$/i.exec(text);
  if (m) {
    const ok = r.pair_code && Date.parse(r.pair_exp) > Date.now() && crypto.timingSafeEqual(Buffer.from(crypto.createHash('sha256').update(m[1].toUpperCase()).digest('hex')), Buffer.from(r.pair_code));
    if (!ok) { audit.log('CHANNEL:' + r.kind, 'CHANNEL_PAIR_FAILED', { id: chId, user: extId }); return { reply: 'That pairing code is wrong or expired. Ask an admin for a new one in PHOENIX X → Channels.' }; }
    db.get().prepare('update channels set pair_code=null, pair_exp=null where id=?').run(chId); allow(chId, extId, true, `${r.kind}:${extId}`);
    return { reply: `✅ Paired. You can now ask me things (try "status") or give commands like "block 203.0.113.9". Decisions that need approval stay in the app.` };
  }
  if (!allowed.includes(extId)) { audit.log('CHANNEL:' + r.kind, 'CHANNEL_UNAUTHORIZED', { id: chId, user: extId }); return { reply: `I don't know you yet. (Your ${r.kind} id is ${extId}.) An admin must press "Pair" in PHOENIX X → Channels, then you send: link <code>`, unauthorized: true }; }
  if (limited(chId + ':' + extId)) return { reply: 'Slow down a little: too many messages in a minute.' };
  const assistant = require('../agents/assistant'), u = { sub: `${r.kind}:${extId}`, role: r.role === 'viewer' ? 'viewer' : 'analyst' };
  audit.log(u.sub, 'CHANNEL_COMMAND', { channel: r.kind, text: text.slice(0, 80) });
  try { return await assistant.handle(u, text, { channel: r.kind }); } catch (e) { return { reply: '⚠️ ' + String(e.message).slice(0, 120) }; }
}
// Slack slash command (form-encoded, HMAC verified)
function verifySlack(c, ts, sig, rawBody) {
  if (!ts || !sig || Math.abs(Date.now() / 1000 - +ts) > 300) return false;
  const exp = 'v0=' + crypto.createHmac('sha256', cfgOf(c).signingSecret).update(`v0:${ts}:${rawBody}`).digest('hex'); const a = Buffer.from(exp), b = Buffer.from(String(sig)); return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function slackInbound(chId, headers, rawBody) {
  const c = raw(chId); if (!c || c.kind !== 'slack') return [404, { error: 'unknown channel' }];
  if (!verifySlack(c, headers['x-slack-request-timestamp'], headers['x-slack-signature'], rawBody)) { audit.log('CHANNEL:slack', 'CHANNEL_SIGNATURE_REJECTED', { id: chId }); return [401, { error: 'bad signature' }]; }
  const f = new URLSearchParams(rawBody), text = f.get('text') || f.get('command') || '', user = f.get('user_id'), respUrl = f.get('response_url');
  const work = command(chId, user, text).then((o) => ({ response_type: 'ephemeral', text: fmt.slack(withChoices(o)) }));
  const first = await Promise.race([work, new Promise((r) => setTimeout(() => r(null), 2500))]);
  if (first) return [200, first];
  work.then((o) => respUrl && hookOk(respUrl, ['slack.com']) && http(respUrl, { method: 'POST', body: o }).catch(() => {}));
  return [200, { response_type: 'ephemeral', text: '⏳ Working on it…' }];
}
// Discord interactions (JSON, Ed25519 verified)
const ED_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function verifyDiscord(c, ts, sig, rawBody) { try { const key = crypto.createPublicKey({ key: Buffer.concat([ED_PREFIX, Buffer.from(cfgOf(c).publicKey, 'hex')]), format: 'der', type: 'spki' }); return crypto.verify(null, Buffer.from(String(ts) + rawBody), key, Buffer.from(String(sig), 'hex')); } catch { return false; } }
async function discordInbound(chId, headers, rawBody) {
  const c = raw(chId); if (!c || c.kind !== 'discord') return [404, { error: 'unknown channel' }];
  if (!verifyDiscord(c, headers['x-signature-timestamp'], headers['x-signature-ed25519'], rawBody)) { audit.log('CHANNEL:discord', 'CHANNEL_SIGNATURE_REJECTED', { id: chId }); return [401, { error: 'bad signature' }]; }
  let b; try { b = JSON.parse(rawBody); } catch { return [400, { error: 'bad json' }]; } if (b.type === 1) return [200, { type: 1 }];
  const user = b.member?.user?.id || b.user?.id, text = (b.data?.options || []).map((o) => o.value).join(' ') || b.data?.name || '';
  const work = command(chId, user, text).then((o) => ({ content: fmt.discord(withChoices(o)) }));
  const first = await Promise.race([work, new Promise((r) => setTimeout(() => r(null), 2500))]);
  if (first) return [200, { type: 4, data: { ...first, flags: 64 } }];
  work.then((o) => b.application_id && b.token && /^[\w-]+$/.test(b.token) && http(`${API.discord()}/webhooks/${b.application_id}/${b.token}/messages/@original`, { method: 'PATCH', body: o }).catch(() => {}));
  return [200, { type: 5, data: { flags: 64 } }];
}
// Telegram long polling
const polling = new Set();
async function pollTelegram(r) {
  if (polling.has(r.id)) return; polling.add(r.id); const cfg = cfgOf(r); let cur = JSON.parse(r.cursor || '{}'), status = 'ok', err = null;
  try {
    const up = await http(`${API.telegram()}/bot${cfg.botToken}/getUpdates?offset=${cur.offset || 0}&timeout=0&allowed_updates=${encodeURIComponent('["message"]')}`);
    for (const u of up.result || []) {
      cur.offset = u.update_id + 1; const m = u.message; if (!m?.text || m.chat?.type !== 'private') continue; // private chats only
      const o = await command(r.id, m.from.id, m.text); await http(`${API.telegram()}/bot${cfg.botToken}/sendMessage`, { method: 'POST', body: { chat_id: m.chat.id, text: fmt.telegram(withChoices(o)) } }).catch((e) => { err = e.message; });
    }
  } catch (e) { status = e.status === 401 ? 'auth_failed' : 'error'; err = e.message; } finally { polling.delete(r.id); }
  db.get().prepare('update channels set cursor=?, last_status=?, last_error=?, last_run=? where id=?').run(JSON.stringify(cur), status, err && String(err).slice(0, 160), new Date().toISOString(), r.id);
}
async function tick() { for (const r of db.get().prepare("select * from channels where kind='telegram' and enabled=1").all()) await pollTelegram(r); }
let timer = null;
const start = (ms = (+process.env.PHOENIX_CHANNEL_POLL_SEC || 3) * 1000) => { stop(); timer = setInterval(() => tick().catch((e) => log.warn?.('channel poll', { error: e.message })), ms); timer.unref?.(); };
const stop = () => { if (timer) clearInterval(timer); timer = null; };

// ---------- outbound ----------
async function sendTo(r, subject, body) {
  const cfg = cfgOf(r), text = subject ? `${subject}\n${body}` : body;
  if (r.kind === 'telegram') { const ids = JSON.parse(r.allow || '[]'); if (!ids.length) throw new Error('no paired chat yet'); for (const id of ids) await http(`${API.telegram()}/bot${cfg.botToken}/sendMessage`, { method: 'POST', body: { chat_id: id, text: fmt.telegram(text) } }); return `${ids.length} chat(s)`; }
  if (r.kind === 'slack') { if (!cfg.webhookUrl) throw new Error('no webhook URL configured'); await http(cfg.webhookUrl, { method: 'POST', body: { text: fmt.slack(subject ? `**${subject}**\n${body}` : body) } }); return 'webhook'; }
  if (r.kind === 'discord') { if (!cfg.webhookUrl) throw new Error('no webhook URL configured'); await http(cfg.webhookUrl, { method: 'POST', body: { content: fmt.discord(subject ? `**${subject}**\n${body}` : body) } }); return 'webhook'; }
  if (r.kind === 'email') { await http(`${API.resend()}/emails`, { method: 'POST', headers: { authorization: 'Bearer ' + cfg.apiKey }, body: { from: cfg.from, to: cfg.to, subject: subject || 'PHOENIX X', text: fmt.email(body) } }); return cfg.to.length + ' recipient(s)'; }
}
const seen = new Set();
async function broadcast(subject, body, { severity = 'high', key = null, force = false } = {}) {
  if (key) { if (seen.has(key)) return []; seen.add(key); if (seen.size > 2000) seen.delete(seen.values().next().value); }
  const out = [];
  for (const r of db.get().prepare('select * from channels where enabled=1').all()) {
    if (!force && (SEV[severity] || 3) < (SEV[r.min_severity] || 3)) continue;
    try { const to = await sendTo(r, subject, body); out.push({ id: r.id, kind: r.kind, ok: true, to }); db.get().prepare("update channels set last_status='ok', last_error=null, last_run=? where id=?").run(new Date().toISOString(), r.id); }
    catch (e) { out.push({ id: r.id, kind: r.kind, ok: false, error: e.message }); if (r.kind !== 'telegram') db.get().prepare("update channels set last_status='error', last_error=?, last_run=? where id=?").run(String(e.message).slice(0, 160), new Date().toISOString(), r.id); }
  }
  if (out.length) audit.log('CHANNELS', 'CHANNEL_BROADCAST', { subject: String(subject).slice(0, 80), sent: out.filter((o) => o.ok).length, failed: out.filter((o) => !o.ok).length });
  return out;
}
async function test(id, by) { const r = raw(id); if (!r) throw new Error('not found'); const res = await sendTo(r, '✅ PHOENIX X test', 'If you can read this, alerts will reach this channel.'); audit.log(by, 'CHANNEL_TEST', { id }); return { ok: true, to: res }; }
// Wire to the event bus: alerts about incidents, approvals waiting, resolutions.
let wired = false;
function wire() {
  if (wired) return; wired = true; const brief = require('../resilience/brief'), link = (p) => (publicUrl() ? `\n${publicUrl()}/#/${p}` : '');
  bus.on('incident', (inc) => { try {
    if (!inc.severity || !SEV[inc.severity]) return;
    if (inc.state === 'RESOLVED') return void broadcast(`✅ Resolved: ${inc.title}`, `${inc.id} was resolved and verified.${link('incidents/' + inc.id)}`, { severity: inc.severity, key: inc.id + ':resolved' });
    if (inc.disposition === 'monitor') return;
    broadcast(`🚨 ${String(inc.severity).toUpperCase()}: ${inc.title}`, brief.text(brief.briefing(inc)) + link('incidents/' + inc.id), { severity: inc.severity, key: inc.id + ':open' });
    if (inc.leak) broadcast('🔑 Leaked secret: ' + inc.id, inc.leak.summary + link('resilience'), { severity: 'critical', key: inc.id + ':leak' });
  } catch (e) { log.warn?.('channel notify', { error: e.message }); } });
  bus.on('approval', (a) => { try { broadcast('⏳ Needs your OK', `${a.action.description || a.action.type} (${a.incidentId}). Approvals are done in the app, not in chat.${link('response')}`, { severity: 'high', key: a.action.id + ':approval' }); } catch { /* ignore */ } });
}
const reset = () => { seen.clear(); rate.clear(); };
module.exports = { SPEC, catalog, list, create, remove, setEnabled, update, pairCode, allow, command, slackInbound, discordInbound, verifySlack, verifyDiscord, tick, start, stop, broadcast, test, wire, reset, fmt };
