'use strict';
// Normalizers: real vendor log formats -> PHOENIX event schema. Each returns an array of raw events (never throws for a
// single bad record; bad records are reported). Unknown record types are kept as low-signal 'api'/'system' events.
const events = require('../core/events');
const P = require('./platforms');

const geoOf = (c) => (c && (c.country || c.city) ? { country: c.country || null, city: c.city || null } : null);
const first = (...v) => v.find((x) => x !== undefined && x !== null && x !== '');

// ---- Okta System Log (GET /api/v1/logs) ----
function okta(r) {
  const t = r.eventType || ''; const ctx = r.client || {};
  const map = { 'user.session.start': r.outcome?.result === 'SUCCESS' ? 'login_success' : 'login_failed', 'user.authentication.auth_via_mfa': 'login_success', 'user.account.lock': 'login_failed', 'user.account.privilege.grant': 'privilege_change', 'group.user_membership.add': 'privilege_change', 'user.account.update_password': 'password_change' };
  const type = map[t] || (r.outcome?.result === 'FAILURE' ? 'login_failed' : 'api_call');
  return { source: type.startsWith('login') ? 'authentication' : 'application', type, ts: r.published, user: first(r.actor?.alternateId, r.actor?.displayName), ip: ctx.ipAddress, device: ctx.device, geo: geoOf(ctx.geographicalContext), outcome: r.outcome?.result === 'SUCCESS' ? 'success' : 'failure', details: { eventType: t, uuid: r.uuid, userAgent: ctx.userAgent?.rawUserAgent, reason: r.outcome?.reason } };
}
// ---- Microsoft Entra ID sign-in logs (Graph /auditLogs/signIns) ----
function entra(r) {
  const ok = String(r.status?.errorCode ?? 0) === '0';
  return { source: 'authentication', type: ok ? 'login_success' : 'login_failed', ts: r.createdDateTime, user: r.userPrincipalName, ip: r.ipAddress, device: r.deviceDetail?.displayName, geo: geoOf({ country: r.location?.countryOrRegion, city: r.location?.city }), outcome: ok ? 'success' : 'failure', resource: r.appDisplayName, details: { appId: r.appId, riskLevel: r.riskLevelDuringSignIn, failure: r.status?.failureReason, conditionalAccess: r.conditionalAccessStatus, id: r.id } };
}
// ---- Windows Security events (4624 logon, 4625 failed, 4720 user created, 4728/4732 group add, 1102 log cleared) ----
function windows(r) {
  const id = +(r.EventID ?? r.event_id ?? r.Id); const d = r.EventData || r.data || r; const ts = first(r.TimeCreated, r.timestamp, r.ts);
  const base = { ts, host: first(r.Computer, r.host, r.hostname), user: first(d.TargetUserName, d.SubjectUserName, r.user), ip: first(d.IpAddress, d.SourceNetworkAddress, r.ip) };
  if (base.ip === '-' || base.ip === '::1') base.ip = null;
  switch (id) {
    case 4624: return { ...base, source: 'authentication', type: 'login_success', outcome: 'success', details: { eventId: id, logonType: d.LogonType } };
    case 4625: return { ...base, source: 'authentication', type: 'login_failed', outcome: 'failure', details: { eventId: id, status: d.Status, logonType: d.LogonType } };
    case 4720: return { ...base, source: 'system', type: 'privilege_change', details: { eventId: id, change: 'account_created' } };
    case 4728: case 4732: case 4756: return { ...base, source: 'system', type: 'privilege_change', details: { eventId: id, group: d.TargetUserName } };
    case 1102: case 104: return { ...base, source: 'system', type: 'stop_logging', details: { eventId: id, note: 'audit log cleared' } };
    case 4688: return { ...base, source: 'system', type: 'process_start', details: { eventId: id, process: d.NewProcessName, commandLine: d.CommandLine } };
    default: return { ...base, source: 'system', type: 'system_event', details: { eventId: id } };
  }
}
// ---- syslog / sshd lines ----
const SSH_FAIL = /Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)/, SSH_OK = /Accepted (?:password|publickey) for (\S+) from (\S+)/;
function syslog(line) {
  const s = String(line); const host = (s.match(/^\S+\s+\d+\s+[\d:]+\s+(\S+)/) || s.match(/^<\d+>\S+\s+\S+\s+(\S+)/) || [])[1] || null;
  let m;
  if ((m = SSH_FAIL.exec(s))) return { source: 'authentication', type: 'login_failed', user: m[1], ip: m[2], host, outcome: 'failure', details: { raw: s.slice(0, 300) } };
  if ((m = SSH_OK.exec(s))) return { source: 'authentication', type: 'login_success', user: m[1], ip: m[2], host, outcome: 'success', details: { raw: s.slice(0, 300) } };
  return { source: 'system', type: 'system_event', host, details: { raw: s.slice(0, 300) } };
}
// ---- CEF (ArcSight Common Event Format) ----
function cef(line) {
  const p = String(line).replace(/^.*?CEF:/, 'CEF:').split(/(?<!\\)\|/); if (p.length < 8) throw new Error('not CEF');
  const ext = {}; for (const m of p.slice(7).join('|').matchAll(/(\w+)=((?:\\.|[^=])*?)(?=\s\w+=|$)/g)) ext[m[1]] = m[2].trim();
  const name = p[5]; const fail = /fail|denied|invalid/i.test(name); const auth = /login|logon|auth/i.test(name);
  return { source: auth ? 'authentication' : 'network', type: auth ? (fail ? 'login_failed' : 'login_success') : 'network_event', ts: ext.rt && /^\d+$/.test(ext.rt) ? new Date(+ext.rt).toISOString() : undefined, user: first(ext.suser, ext.duser), ip: first(ext.src, ext.dst), host: first(ext.dhost, ext.shost), outcome: fail ? 'failure' : 'success', details: { cefName: name, vendor: p[1], product: p[2], severity: p[6], ext } };
}

const generic = (r) => r; // already in PHOENIX schema
const lines = (b) => (Array.isArray(b?.lines) ? b.lines : typeof b?.lines === 'string' ? b.lines.split(/\r?\n/) : []);

const FORMATS = {
  generic: (b) => (Array.isArray(b.events) ? b.events : []).map(generic),
  okta: (b) => (Array.isArray(b) ? b : b.events || []).map(okta),
  entra: (b) => (Array.isArray(b) ? b : b.value || b.events || []).map(entra),
  cloudtrail: (b) => (b.Records || []).map(events.fromCloudTrail),
  windows: (b) => (Array.isArray(b) ? b : b.events || []).map(windows),
  syslog: (b) => (Array.isArray(b.lines) ? b.lines : typeof b.lines === 'string' ? b.lines.split(/\r?\n/) : []).filter(Boolean).map(syslog),
  cef: (b) => (Array.isArray(b.lines) ? b.lines : typeof b.lines === 'string' ? b.lines.split(/\r?\n/) : []).filter(Boolean).map(cef),
  // ---- deployment platforms & web servers (see platforms.js) ----
  vercel: P.vercel, 'vercel-webhook': P['vercel-webhook'], render: P.render, 'render-webhook': P['render-webhook'], heroku: P.heroku, netlify: P.netlify, railway: P.railway, cloudflare: P.cloudflare, github: P.github, nginx: P.nginx,
};
const MAX = 1000;
// Returns { accepted, rejected:[{index,error}], duplicates }
const seen = new Map(); // dedupe key -> ts (bounded)
function ingest(format, body) {
  const fn = FORMATS[format]; if (!fn) throw new Error('unknown format ' + format);
  let list; try { list = fn(body || {}); } catch (e) { throw new Error('malformed payload: ' + e.message); }
  if (list.length > MAX) throw new Error(`too many records (max ${MAX} per request)`);
  const out = { accepted: 0, duplicates: 0, rejected: [], ignored: 0 }; const now = Date.now();
  for (const [k, t] of seen) if (now - t > 3600e3) seen.delete(k); if (seen.size > 50000) seen.clear();
  const before = list.length; list = list.flat().filter(Boolean); out.ignored = Math.max(0, before - list.length);
  list.forEach((raw, i) => {
    try {
      const key = raw.dedupeKey || raw.id || raw.details?.uuid || raw.details?.eventID || raw.details?.id; if (key) { if (seen.has(format + key)) { out.duplicates++; return; } seen.set(format + key, now); }
      const { dedupeKey, ...ev } = raw; events.add({ ...ev, origin: 'ingested' }); out.accepted++;
    } catch (e) { out.rejected.push({ index: i, error: e.message }); }
  });
  return out;
}
module.exports = { ingest, FORMATS: Object.keys(FORMATS), okta, entra, windows, syslog, cef };
