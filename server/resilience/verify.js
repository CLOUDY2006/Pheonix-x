'use strict';
// RECOVERY VERIFICATION ENGINE. Pass/fail comes from real HTTP probes you define, never from an AI saying "done".
// Check types: http (status/body/latency), json_value (e.g. error rate <= 2%), rejects_credential (the OLD key must now be refused),
// accepts_credential (the NEW key works). Credentials used by checks are stored AES-GCM encrypted and never returned.
// SSRF guard: https only, and private/loopback/link-local/metadata addresses are refused (set PHOENIX_VERIFY_ALLOW_PRIVATE=1 for tests/self-hosting).
const dns = require('dns').promises; const net = require('net'); const crypto = require('crypto');
const db = require('../core/db'); const audit = require('../core/audit'); const secrets = require('../core/secrets');

const TYPES = { http: 'Endpoint health', json_value: 'Metric threshold', rejects_credential: 'Old credential rejected', accepts_credential: 'New credential works' };
const allowPrivate = () => process.env.PHOENIX_VERIFY_ALLOW_PRIVATE === '1';
function privateIp(ip) {
  if (net.isIPv6(ip)) { const l = ip.toLowerCase(); return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb') || (l.startsWith('::ffff:') && privateIp(l.slice(7))); }
  const p = ip.split('.').map(Number); if (p.length !== 4) return true;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || p[0] >= 224;
}
async function guard(u) {
  let url; try { url = new URL(u); } catch { throw new Error('invalid URL'); }
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('only http(s) URLs');
  if (url.protocol === 'http:' && !allowPrivate()) throw new Error('https required');
  if (url.username || url.password) throw new Error('credentials in URL are not allowed');
  if (!allowPrivate()) { const addrs = net.isIP(url.hostname) ? [{ address: url.hostname }] : await dns.lookup(url.hostname, { all: true }); if (!addrs.length || addrs.some((a) => privateIp(a.address))) throw new Error('target resolves to a private/internal address (blocked)'); }
  return url;
}
function cleanConfig(type, c = {}) {
  if (!TYPES[type]) throw new Error('type must be one of ' + Object.keys(TYPES).join(', '));
  const o = { url: String(c.url || '').trim(), method: ['GET', 'POST'].includes(String(c.method || 'GET').toUpperCase()) ? String(c.method || 'GET').toUpperCase() : 'GET' };
  if (!/^https?:\/\//i.test(o.url)) throw new Error('url required (https://…)');
  if (type === 'http' || type === 'accepts_credential') o.expectStatus = +c.expectStatus || 200;
  if (type === 'http' && c.contains) o.contains = String(c.contains).slice(0, 200);
  if (c.maxMs) o.maxMs = Math.min(60000, +c.maxMs || 0) || undefined;
  if (c.body && o.method === 'POST') o.body = String(c.body).slice(0, 2000);
  if (type === 'json_value') { o.path = String(c.path || '').slice(0, 80); o.op = ['<=', '>=', '==', '<', '>'].includes(c.op) ? c.op : '<='; o.value = Number(c.value); if (!o.path || !Number.isFinite(o.value)) throw new Error('path and numeric value required'); }
  if (type === 'rejects_credential' || type === 'accepts_credential') { o.header = /^[A-Za-z-]{1,40}$/.test(c.header || '') ? c.header : 'authorization'; o.prefix = c.prefix === undefined ? 'Bearer ' : String(c.prefix).slice(0, 20); }
  return o;
}
const row = (r) => r && ({ id: r.id, node: r.node, name: r.name, type: r.type, label: TYPES[r.type], config: JSON.parse(r.config || '{}'), hasSecret: !!r.secret_enc, required: !!r.required, createdBy: r.created_by, createdAt: r.created_at });
const list = (node) => db.get().prepare(node ? 'select * from rz_checks where node=? order by created_at' : 'select * from rz_checks order by created_at').all(...(node ? [node] : [])).map(row);
function add({ node = null, name, type, config, secret, required = true }, by) {
  const cfg = cleanConfig(type, config); if (!name) throw new Error('name required');
  if ((type === 'rejects_credential' || type === 'accepts_credential') && (!secret || String(secret).length < 4)) throw new Error('credential value required for this check type');
  const id = 'chk-' + crypto.randomBytes(4).toString('hex');
  db.get().prepare('insert into rz_checks(id,node,name,type,config,secret_enc,required,created_by,created_at) values(?,?,?,?,?,?,?,?,?)').run(id, node, String(name).slice(0, 100), type, JSON.stringify(cfg), secret ? secrets.encrypt(String(secret)) : null, required ? 1 : 0, by, new Date().toISOString());
  audit.log(by, 'RZ_CHECK_ADDED', { id, type, node }); return row(db.get().prepare('select * from rz_checks where id=?').get(id));
}
function remove(id, by) { const r = db.get().prepare('delete from rz_checks where id=?').run(id); audit.log(by, 'RZ_CHECK_REMOVED', { id }); return r.changes > 0; }

async function probe(url, cfg, headers = {}) {
  const u = await guard(url), t0 = Date.now(), ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 15000);
  try { const r = await fetch(u, { method: cfg.method || 'GET', redirect: 'manual', signal: ctl.signal, headers: { 'user-agent': 'phoenix-x-verify', ...(cfg.body ? { 'content-type': 'application/json' } : {}), ...headers }, body: cfg.body }); const text = await r.text(); return { status: r.status, ms: Date.now() - t0, text: text.slice(0, 200000) }; }
  catch (e) { if (e.name === 'AbortError') throw new Error('timed out after 15s'); throw e; } finally { clearTimeout(to); }
}
const OPS = { '<=': (a, b) => a <= b, '>=': (a, b) => a >= b, '==': (a, b) => a === b, '<': (a, b) => a < b, '>': (a, b) => a > b };
async function runCheck(r) {
  const cfg = JSON.parse(r.config), out = { id: r.id, name: r.name, type: r.type, node: r.node, required: !!r.required, ok: false, detail: '', ms: null };
  try {
    const hdr = r.secret_enc ? { [cfg.header || 'authorization']: (cfg.prefix ?? 'Bearer ') + secrets.decrypt(r.secret_enc) } : {};
    const p = await probe(cfg.url, cfg, hdr); out.ms = p.ms; out.status = p.status;
    if (r.type === 'http' || r.type === 'accepts_credential') { out.ok = p.status === (cfg.expectStatus || 200); out.detail = `HTTP ${p.status}, expected ${cfg.expectStatus || 200}`; if (out.ok && cfg.contains) { out.ok = p.text.includes(cfg.contains); out.detail += out.ok ? `, body contains "${cfg.contains}"` : `, body is missing "${cfg.contains}"`; } }
    else if (r.type === 'rejects_credential') { out.ok = [401, 403].includes(p.status); out.detail = out.ok ? `old credential refused (HTTP ${p.status})` : `old credential still ACCEPTED (HTTP ${p.status}) - it has not been revoked`; }
    else if (r.type === 'json_value') { let v; try { v = cfg.path.split('.').reduce((o, k) => (o == null ? o : o[k]), JSON.parse(p.text)); } catch { v = undefined; } v = Number(v); out.ok = Number.isFinite(v) && OPS[cfg.op](v, cfg.value); out.detail = Number.isFinite(v) ? `${cfg.path}=${v} (need ${cfg.op} ${cfg.value})` : `${cfg.path} not found / not numeric in response`; }
    if (out.ok && cfg.maxMs && p.ms > cfg.maxMs) { out.ok = false; out.detail += `; too slow (${p.ms}ms > ${cfg.maxMs}ms)`; }
  } catch (e) { out.ok = false; out.detail = String(e.message).slice(0, 160); }
  return out;
}
// Run all checks (optionally only those for given node ids; checks with no node are global and always run).
async function run({ nodes = null, ref = null, by = 'system' } = {}) {
  const all = db.get().prepare('select * from rz_checks order by created_at').all().filter((r) => !nodes || !r.node || nodes.includes(r.node));
  const results = []; for (const r of all) results.push(await runCheck(r));
  const failedReq = results.filter((x) => !x.ok && x.required).length;
  const report = { id: 'ver-' + crypto.randomBytes(4).toString('hex'), at: new Date().toISOString(), ref, total: results.length, passed: results.filter((x) => x.ok).length, failed: results.filter((x) => !x.ok).length, failedRequired: failedReq, verdict: !results.length ? 'NO_CHECKS' : failedReq ? 'FAILED' : results.some((x) => !x.ok) ? 'PASSED_WITH_WARNINGS' : 'PASSED', results };
  report.sha256 = crypto.createHash('sha256').update(JSON.stringify({ at: report.at, ref, results })).digest('hex');
  db.get().prepare('insert into rz_runs(id,kind,ref,status,result,by,at) values(?,?,?,?,?,?,?)').run(report.id, 'verify', ref, report.verdict, JSON.stringify(report), by, report.at);
  audit.log(by, 'RZ_VERIFIED', { id: report.id, verdict: report.verdict, passed: report.passed, failed: report.failed, ref }); return report;
}
const reports = (limit = 20) => db.get().prepare("select result from rz_runs where kind='verify' order by at desc limit ?").all(limit).map((r) => JSON.parse(r.result));
module.exports = { TYPES, add, list, remove, run, reports, guard, privateIp, cleanConfig };
