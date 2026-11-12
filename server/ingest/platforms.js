'use strict';
// Deployment-platform & web-server normalizers. Each parser takes the parsed request body and returns an array of
// PHOENIX events (or null/[] to ignore). Field mappings follow each vendor's published schema; unknown record types are
// ignored rather than guessed. Web requests become `web_request` events; account/config changes become `platform_change`.
const AUTH_PATH = /^\/(api\/)?(auth|login|signin|sign-in|session|token|oauth|wp-login\.php|users\/sign_in|admin\/login)(\/|\?|$)/i;
const toArr = (b) => (Array.isArray(b) ? b : b && typeof b === 'object' ? [b] : []);
const first = (...v) => v.find((x) => x !== undefined && x !== null && x !== '');
const iso = (t) => { if (t === undefined || t === null || t === '') return undefined; const d = typeof t === 'number' ? new Date(t > 1e12 ? t : t * 1000) : new Date(t); return isNaN(d) ? undefined : d.toISOString(); };
const stripQuery = (p) => String(p || '').slice(0, 300);

// One HTTP request seen by a platform => web_request (+ login_failed when an auth endpoint rejects the caller).
function web({ platform, ts, ip, host, method, path, status, ua, country, region, project, action }) {
  if (!ip) return [];
  const st = Number(status) || 0; const out = [];
  const base = { ts, ip, host: host || null, resource: stripQuery(path), geo: country ? { country } : null };
  out.push({ ...base, source: 'network', type: 'web_request', outcome: st >= 400 || st === -1 ? 'failure' : 'success', details: { platform, method, status: st, userAgent: ua ? String(ua).slice(0, 160) : undefined, region, project, waf: action } });
  if ((st === 401 || st === 403) && (method || 'GET').toUpperCase() === 'POST' && AUTH_PATH.test(String(path || '').split('?')[0])) out.push({ ...base, source: 'authentication', type: 'login_failed', outcome: 'failure', user: undefined, details: { platform, via: 'http-status', status: st, path: stripQuery(path).split('?')[0] } });
  return out;
}
const wafEvt = (o) => ({ source: 'network', type: 'waf_block', ts: o.ts, ip: o.ip, host: o.host || null, resource: stripQuery(o.path), geo: o.country ? { country: o.country } : null, outcome: 'blocked', details: { platform: o.platform, action: o.action, rule: o.rule, method: o.method } });
const change = (o) => ({ source: o.source || 'application', type: 'platform_change', ts: o.ts, user: undefined, ip: o.ip || null, resource: o.resource || null, outcome: o.outcome || 'success', details: { platform: o.platform, change: o.change, actor: o.actor || null, what: o.what, severity: o.severity, id: o.id, raw: o.raw } });
const deploy = (o) => ({ source: 'application', type: 'deploy_event', ts: o.ts, ip: null, resource: o.resource || null, outcome: o.outcome || 'success', details: { platform: o.platform, actor: o.actor || null, status: o.status, env: o.env, branch: o.branch, commit: o.commit, id: o.id } });

// ---------------------------------------------------------------- Vercel
// Log Drain: JSON array or NDJSON of log objects {id,source,timestamp,proxy{clientIp,method,path,statusCode,userAgent[],region,host,wafAction,wafRuleId},...}
function vercel(body) {
  const out = [];
  for (const l of toArr(body)) {
    if (!l || typeof l !== 'object') continue;
    const p = l.proxy || null; const ts = iso(l.timestamp || p?.timestamp);
    if (p && (p.wafAction && !/^(log|allow|none|bypass)$/i.test(p.wafAction))) out.push({ ...wafEvt({ platform: 'vercel', ts, ip: p.clientIp, host: p.host, path: p.path, action: p.wafAction, rule: p.wafRuleId, method: p.method }), dedupeKey: l.id && l.id + ':waf' });
    if (p) { out.push(...web({ platform: 'vercel', ts, ip: p.clientIp, host: p.host, method: p.method, path: p.path, status: p.statusCode ?? l.statusCode, ua: Array.isArray(p.userAgent) ? p.userAgent[0] : p.userAgent, region: p.region, project: l.projectName || l.projectId, action: p.wafAction }).map((e) => ({ ...e, dedupeKey: e.type === 'web_request' && l.id ? l.id + ':req' : undefined }))); continue; }
    if (l.source === 'firewall') continue; // firewall logs without proxy data carry nothing we can use
    if (/^(error|fatal)$/i.test(l.level) && l.source !== 'build') out.push({ source: 'application', type: 'app_error', ts, resource: l.path || l.host || null, outcome: 'failure', details: { platform: 'vercel', source: l.source, message: String(l.message || '').slice(0, 200), id: l.id } });
  }
  return out;
}
// Webhooks: {id,type,createdAt,payload:{...}}
function vercelWebhook(body) {
  const t = String(body?.type || ''); const p = body?.payload || {}; const ts = iso(body?.createdAt); const actor = first(p.user?.username, p.user?.email, p.user?.id);
  const res = first(p.deployment?.name, p.project?.name, p.domain?.name, p.name);
  if (/^deployment\./.test(t)) return [deploy({ platform: 'vercel', ts, resource: res, outcome: /error|canceled/.test(t) ? 'failure' : 'success', status: t.split('.')[1], env: p.target || p.deployment?.target, actor, id: body.id })];
  if (/^domain\.(created|removed|deleted|transferred)/.test(t)) return [change({ platform: 'vercel', ts, change: 'domain_changed', what: t, actor, resource: res, id: body.id })];
  if (/^project\.(removed|deleted)/.test(t)) return [change({ platform: 'vercel', ts, change: 'project_deleted', what: t, actor, resource: res, id: body.id })];
  if (/^integration-configuration\.(removed|scope-change)/.test(t)) return [change({ platform: 'vercel', ts, change: 'integration_changed', what: t, actor, resource: res, id: body.id })];
  if (/firewall|attack/.test(t)) return [change({ platform: 'vercel', ts, change: 'waf_attack_signal', what: t, actor, resource: res, id: body.id })];
  return [];
}
// ---------------------------------------------------------------- Render
// Webhook: {type:'deploy_ended'|'server_failed'|..., timestamp, data:{id,serviceId,serviceName,status,...}}
function renderWebhook(body) {
  const t = String(body?.type || ''); const d = body?.data || {}; const ts = iso(body?.timestamp);
  if (/^deploy_/.test(t)) return [deploy({ platform: 'render', ts, resource: first(d.serviceName, d.serviceId), outcome: /fail|cancel/i.test(String(d.status)) ? 'failure' : 'success', status: first(d.status, t), id: d.id })];
  if (/service_(suspended|resumed|deleted)|env_?var|secret/i.test(t)) return [change({ platform: 'render', ts, change: /env|secret/i.test(t) ? 'env_var_changed' : 'service_state_changed', what: t, resource: first(d.serviceName, d.serviceId), id: d.id })];
  return [];
}
// Log stream lines (RFC5424 syslog, relayed over HTTP by Vector/Fluent Bit/etc.). Only structured request records are used.
const SYSLOG5424 = /^(?:\d+\s+)?<(\d+)>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:-|\[[^\]]*\])\s?(.*)$/s;
function kv(msg) { const o = {}; for (const m of String(msg).matchAll(/(\w[\w.-]*)=(?:"([^"]*)"|(\S+))/g)) o[m[1]] = m[2] ?? m[3]; return o; }
function render(body) {
  const lines = Array.isArray(body?.lines) ? body.lines : typeof body?.lines === 'string' ? body.lines.split(/\r?\n/) : [];
  const out = [];
  for (const line of lines) {
    const m = SYSLOG5424.exec(String(line).trim()); if (!m) continue; const msg = m[7]; let o = null;
    try { if (msg.startsWith('{')) o = JSON.parse(msg); } catch { /* logfmt below */ }
    o ||= kv(msg);
    const ip = first(o.ip, o.client_ip, o.clientIp, o.remote_addr, o.remoteIp, o.fwd); const path = first(o.path, o.url, o.uri), status = first(o.status, o.statusCode, o.status_code);
    if (ip && path && status) out.push(...web({ platform: 'render', ts: iso(m[2]), ip: String(ip).split(',')[0].trim(), host: first(o.host, m[3]), method: first(o.method, 'GET'), path, status, ua: first(o.user_agent, o.ua), project: m[3] }));
  }
  return out;
}
// ---------------------------------------------------------------- Heroku (Logplex HTTPS drain, octet-counted syslog)
function logplexFrames(text) {
  const out = []; let i = 0; const s = Buffer.from(String(text), 'utf8');
  while (i < s.length) { let j = i; while (j < s.length && s[j] >= 48 && s[j] <= 57) j++; if (j === i || s[j] !== 32) break; const n = +s.slice(i, j).toString(); const start = j + 1; if (start + n > s.length) { out.push(s.slice(start).toString('utf8')); break; } out.push(s.slice(start, start + n).toString('utf8')); i = start + n; }
  return out;
}
function heroku(body) {
  const text = typeof body?.lines === 'string' ? body.lines : Array.isArray(body?.lines) ? body.lines.join('\n') : '';
  const frames = /^\d+ </.test(text) ? logplexFrames(text) : text.split(/\r?\n/);
  const out = [];
  for (const f of frames) {
    const m = /^<\d+>1\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+(.*)$/s.exec(f.trim()); if (!m) continue; const [, ts, app, proc, msg] = m;
    if (app === 'heroku' && proc === 'router') { const o = kv(msg); const ip = String(o.fwd || '').split(',')[0].trim(); if (ip) out.push(...web({ platform: 'heroku', ts: iso(ts), ip, host: o.host, method: o.method, path: o.path, status: o.status, project: undefined })); continue; }
    if (app === 'heroku' && /^api$/.test(proc)) {
      let x;
      if ((x = /^(Set|Unset|Remove) (.+?) config vars? by user (\S+)/i.exec(msg))) out.push(change({ platform: 'heroku', ts: iso(ts), change: 'env_var_changed', what: `${x[1]} ${x[2]}`, actor: x[3] }));
      else if ((x = /^Deploy (\S+) by user (\S+)/i.exec(msg))) out.push(deploy({ platform: 'heroku', ts: iso(ts), actor: x[2], commit: x[1], status: 'deployed' }));
      else if ((x = /^(Add|Remove) domain (\S+) by user (\S+)/i.exec(msg)) || (x = /^(Add|Remove)d? (collaborator|domain) (\S+) by user (\S+)/i.exec(msg))) out.push(change({ platform: 'heroku', ts: iso(ts), change: /collaborator/i.test(msg) ? 'member_added' : 'domain_changed', what: msg.slice(0, 120), actor: x[x.length - 1] }));
    }
  }
  return out;
}
// ---------------------------------------------------------------- Netlify deploy notification (deploy object)
function netlify(body) {
  const b = body || {}; if (!b.id && !b.site_id) return [];
  const state = String(b.state || ''); return [deploy({ platform: 'netlify', ts: iso(first(b.published_at, b.updated_at, b.created_at)), resource: first(b.name, b.site_id), outcome: /error|failed/i.test(state) ? 'failure' : 'success', status: state, env: b.context, branch: b.branch, commit: b.commit_ref, actor: first(b.committer, b.deploy_ssl_url && undefined), id: b.id })];
}
// ---------------------------------------------------------------- Railway deployment webhook (defensive mapping)
function railway(body) {
  const b = body || {}; const d = b.deployment || {}; const status = String(first(b.status, d.status, '')).toUpperCase(); if (!status && !b.type) return [];
  return [deploy({ platform: 'railway', ts: iso(first(b.timestamp, b.createdAt)), resource: first(b.service?.name, b.project?.name), outcome: /FAIL|CRASH|ERROR/.test(status) ? 'failure' : 'success', status: status || b.type, env: b.environment?.name, actor: first(d.creator?.name, d.creator?.email), id: d.id })];
}
// ---------------------------------------------------------------- Cloudflare Logpush (http_requests / firewall_events), NDJSON
function cloudflare(body) {
  const out = [];
  for (const r of toArr(body)) {
    if (!r || typeof r !== 'object' || r.content === 'tests') continue;
    if (r.Action !== undefined && r.ClientIP) { // firewall_events
      const act = String(r.Action); const ts = iso(first(r.Datetime, r.EdgeStartTimestamp));
      if (!/^(log|allow|skip|bypass)$/i.test(act)) out.push(wafEvt({ platform: 'cloudflare', ts, ip: r.ClientIP, host: r.ClientRequestHost, path: first(r.ClientRequestPath, r.ClientRequestURI), action: act, rule: first(r.RuleID, r.Source), method: r.ClientRequestMethod, country: r.ClientCountry }));
      continue;
    }
    if (r.ClientIP && (r.ClientRequestPath || r.ClientRequestURI)) out.push(...web({ platform: 'cloudflare', ts: iso(first(r.EdgeStartTimestamp, r.EdgeEndTimestamp)), ip: r.ClientIP, host: r.ClientRequestHost, method: r.ClientRequestMethod, path: first(r.ClientRequestURI, r.ClientRequestPath), status: first(r.EdgeResponseStatus, r.OriginResponseStatus), ua: r.ClientRequestUserAgent, country: r.ClientCountry }));
  }
  return out;
}
// ---------------------------------------------------------------- GitHub webhooks (event name from header X-GitHub-Event, injected as body.__event by the route)
function github(body) {
  const b = body || {}; const ev = b.__event || ''; const repo = b.repository?.full_name; const actor = first(b.sender?.login); const ts = iso(first(b.alert?.created_at, b.repository?.updated_at)) || undefined;
  const mk = (c, what, extra = {}) => [change({ platform: 'github', ts, change: c, what, actor, resource: repo || b.organization?.login, ...extra })];
  if (ev === 'ping') return [];
  if (ev === 'secret_scanning_alert' && b.action === 'created') return mk('secret_exposed', `secret scanning: ${b.alert?.secret_type_display_name || b.alert?.secret_type || 'secret'}`);
  if (ev === 'repository' && b.action === 'publicized') return mk('repo_public', 'repository made public');
  if (ev === 'repository' && b.action === 'deleted') return mk('project_deleted', 'repository deleted');
  if (ev === 'deploy_key' && b.action === 'created') return mk('deploy_key_added', `deploy key "${b.key?.title || ''}" ${b.key?.read_only === false ? '(WRITE access)' : ''}`);
  if (ev === 'branch_protection_rule' && b.action === 'deleted') return mk('branch_protection_removed', `branch protection removed (${b.rule?.name || ''})`);
  if ((ev === 'member' && b.action === 'added') || (ev === 'organization' && /member_(added|invited)/.test(b.action))) return mk('member_added', `${b.member?.login || b.membership?.user?.login || b.invitation?.login || 'user'} added`);
  if (ev === 'push' && b.forced && /refs\/heads\/(main|master|production|prod|release)/.test(b.ref || '')) return mk('force_push', `force-push to ${b.ref}`);
  if (ev === 'dependabot_alert' && b.action === 'created' && /critical/i.test(b.alert?.security_advisory?.severity || '')) return mk('vuln_critical', `critical dependency vulnerability: ${b.alert?.security_advisory?.summary || ''}`.slice(0, 160));
  return [];
}
// ---------------------------------------------------------------- nginx / Apache "combined" access-log lines
const COMBINED = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (?:\d+|-)(?: "[^"]*" "([^"]*)")?/;
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
function clfTime(s) { const m = /^(\d+)\/(\w+)\/(\d+):(\d+):(\d+):(\d+) ([+-])(\d\d)(\d\d)$/.exec(s); if (!m) return undefined; const t = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]) - (m[7] === '-' ? -1 : 1) * (+m[8] * 60 + +m[9]) * 60000; return new Date(t).toISOString(); }
function nginx(body) {
  const lines = Array.isArray(body?.lines) ? body.lines : typeof body?.lines === 'string' ? body.lines.split(/\r?\n/) : [];
  const out = [];
  for (const line of lines) { const m = COMBINED.exec(String(line)); if (!m) continue; out.push(...web({ platform: 'web-server', ts: clfTime(m[3]), ip: m[1], method: m[4], path: m[5], status: m[6], ua: m[7] })); }
  return out;
}

module.exports = { vercel, 'vercel-webhook': vercelWebhook, 'render-webhook': renderWebhook, render, heroku, netlify, railway, cloudflare, github, nginx, logplexFrames, kv };
