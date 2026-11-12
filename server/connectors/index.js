'use strict';
// Connectors: how GUARDIAN reaches the real world. One adapter per containment domain.
//   identity -> disable_account, revoke_sessions, revoke_token      (okta | entra | webhook)
//   network  -> block_ip                                            (webhook)
//   endpoint -> isolate_host                                        (webhook)
//   data     -> restrict_resource                                   (webhook)
//   cloud    -> detach_cloud_policy, make_bucket_private            (webhook)
//   sim      -> the in-memory simulator (demo mode only)   none -> nothing connected: human must act
// Safety: every live call is skipped while PHOENIX_CONNECTOR_DRYRUN=on (default). A call only counts as done when the
// provider's own response / a read-back post-check confirms it.
const crypto = require('crypto');
const cfg = require('../core/config');

const DOMAIN = { force_password_reset: 'identity', disable_account: 'identity', revoke_sessions: 'identity', revoke_token: 'identity', block_ip: 'network', isolate_host: 'endpoint', restrict_resource: 'data', detach_cloud_policy: 'cloud', make_bucket_private: 'cloud' };
const E = () => process.env;
const T = 10000;
async function http(method, url, { headers = {}, body, form } = {}) {
  const r = await fetch(url, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...headers }, body: form ? new URLSearchParams(form).toString() : body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(T) });
  let j = null; const txt = await r.text(); try { j = txt ? JSON.parse(txt) : null; } catch { /* non-JSON */ }
  return { ok: r.ok, status: r.status, json: j };
}

// ---------- generic signed webhook ----------
const webhook = {
  name: 'webhook',
  supports: (type) => !!DOMAIN[type],
  async call(kind, type, target, ctx) {
    const url = E()['PHOENIX_WEBHOOK_URL_' + DOMAIN[type].toUpperCase()] || E().PHOENIX_WEBHOOK_URL; if (!url) throw new Error('PHOENIX_WEBHOOK_URL not set');
    const body = JSON.stringify({ kind, action: type, target, incidentId: ctx.incidentId || null, requestedBy: ctx.by || null, actionId: ctx.actionId, ts: new Date().toISOString() });
    const headers = { 'content-type': 'application/json', 'Idempotency-Key': `${ctx.actionId}:${kind}` };
    if (E().PHOENIX_WEBHOOK_SECRET) headers['X-Phoenix-Signature'] = 'sha256=' + crypto.createHmac('sha256', E().PHOENIX_WEBHOOK_SECRET).update(body).digest('hex');
    const r = await fetch(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(T) }); let j = null; try { j = await r.json(); } catch { /* empty */ }
    if (!r.ok) throw new Error(`webhook HTTP ${r.status}`);
    return { provider: 'webhook', providerConfirmed: j ? j.confirmed !== false : true, detail: j?.detail || `${type} delivered to webhook (HTTP ${r.status})` };
  },
  run(type, target, ctx) { return this.call('execute', type, target, ctx); },
  undo(type, target, ctx) { return this.call('rollback', type, target, ctx); },
};

// ---------- Okta ----------
const okta = {
  name: 'okta',
  supports: (type) => ['disable_account', 'revoke_sessions', 'force_password_reset'].includes(type),
  h: () => ({ Authorization: 'SSWS ' + E().OKTA_API_TOKEN, accept: 'application/json' }),
  base: () => { const u = E().OKTA_URL; if (!u || !E().OKTA_API_TOKEN) throw new Error('OKTA_URL and OKTA_API_TOKEN required'); return u.replace(/\/$/, ''); },
  async run(type, t) {
    const b = this.base(), u = encodeURIComponent(t.user);
    if (type === 'force_password_reset') {
      const r = await http('POST', `${b}/api/v1/users/${u}/lifecycle/expire_password`, { headers: this.h() }); if (!r.ok) throw new Error('Okta expire_password HTTP ' + r.status);
      await http('DELETE', `${b}/api/v1/users/${u}/sessions`, { headers: this.h() });
      return { provider: 'okta', providerConfirmed: r.json?.status === 'PASSWORD_EXPIRED', detail: `Okta user ${t.user} status=${r.json?.status}` };
    }
    if (type === 'disable_account') {
      const r = await http('POST', `${b}/api/v1/users/${u}/lifecycle/suspend`, { headers: this.h() }); if (!r.ok && r.status !== 400) throw new Error('Okta suspend HTTP ' + r.status); // 400 = already suspended
      const g = await http('GET', `${b}/api/v1/users/${u}`, { headers: this.h() });
      return { provider: 'okta', providerConfirmed: g.ok && g.json?.status === 'SUSPENDED', detail: `Okta user ${t.user} status=${g.json?.status}` };
    }
    const r = await http('DELETE', `${b}/api/v1/users/${u}/sessions`, { headers: this.h() }); if (!r.ok) throw new Error('Okta clear sessions HTTP ' + r.status);
    return { provider: 'okta', providerConfirmed: true, detail: `Okta sessions cleared for ${t.user}` };
  },
  async undo(type, t) {
    if (type !== 'disable_account') return { provider: 'okta', providerConfirmed: true, detail: 'nothing to undo' };
    const b = this.base(), u = encodeURIComponent(t.user); const r = await http('POST', `${b}/api/v1/users/${u}/lifecycle/unsuspend`, { headers: this.h() }); if (!r.ok) throw new Error('Okta unsuspend HTTP ' + r.status);
    const g = await http('GET', `${b}/api/v1/users/${u}`, { headers: this.h() }); return { provider: 'okta', providerConfirmed: g.json?.status === 'ACTIVE', detail: `Okta user ${t.user} status=${g.json?.status}` };
  },
};

// ---------- Microsoft Entra ID (Graph) ----------
let tokCache = { v: null, exp: 0 };
const entra = {
  name: 'entra',
  supports: (type) => ['disable_account', 'revoke_sessions', 'force_password_reset'].includes(type),
  async token() {
    if (tokCache.v && tokCache.exp > Date.now() + 60e3) return tokCache.v;
    const { ENTRA_TENANT_ID: tn, ENTRA_CLIENT_ID: id, ENTRA_CLIENT_SECRET: sec } = E(); if (!tn || !id || !sec) throw new Error('ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET required');
    const auth = (E().ENTRA_AUTHORITY || 'https://login.microsoftonline.com').replace(/\/$/, '');
    const r = await http('POST', `${auth}/${tn}/oauth2/v2.0/token`, { form: { client_id: id, client_secret: sec, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' } });
    if (!r.ok || !r.json?.access_token) throw new Error('Entra token HTTP ' + r.status); tokCache = { v: r.json.access_token, exp: Date.now() + (r.json.expires_in || 3000) * 1000 }; return tokCache.v;
  },
  graph: () => (E().ENTRA_GRAPH || 'https://graph.microsoft.com').replace(/\/$/, ''),
  async run(type, t) {
    const h = { Authorization: 'Bearer ' + await this.token() }, u = encodeURIComponent(t.user), g = this.graph();
    if (type === 'force_password_reset') {
      const r = await http('PATCH', `${g}/v1.0/users/${u}`, { headers: h, body: { passwordProfile: { forceChangePasswordNextSignIn: true } } }); if (!r.ok) throw new Error('Graph password-reset HTTP ' + r.status);
      await http('POST', `${g}/v1.0/users/${u}/revokeSignInSessions`, { headers: h });
      return { provider: 'entra', providerConfirmed: true, detail: `Entra: ${t.user} must change password at next sign-in (provider returned success)` };
    }
    if (type === 'disable_account') {
      const r = await http('PATCH', `${g}/v1.0/users/${u}`, { headers: h, body: { accountEnabled: false } }); if (!r.ok) throw new Error('Graph disable HTTP ' + r.status);
      await http('POST', `${g}/v1.0/users/${u}/revokeSignInSessions`, { headers: h });
      const c = await http('GET', `${g}/v1.0/users/${u}?$select=accountEnabled`, { headers: h }); return { provider: 'entra', providerConfirmed: c.ok && c.json?.accountEnabled === false, detail: `Entra accountEnabled=${c.json?.accountEnabled}` };
    }
    const r = await http('POST', `${g}/v1.0/users/${u}/revokeSignInSessions`, { headers: h }); if (!r.ok) throw new Error('Graph revoke HTTP ' + r.status);
    return { provider: 'entra', providerConfirmed: r.json?.value !== false, detail: `Entra sign-in sessions revoked for ${t.user}` };
  },
  async undo(type, t) {
    if (type !== 'disable_account') return { provider: 'entra', providerConfirmed: true, detail: 'nothing to undo' };
    const h = { Authorization: 'Bearer ' + await this.token() }, u = encodeURIComponent(t.user), g = this.graph();
    const r = await http('PATCH', `${g}/v1.0/users/${u}`, { headers: h, body: { accountEnabled: true } }); if (!r.ok) throw new Error('Graph enable HTTP ' + r.status);
    const c = await http('GET', `${g}/v1.0/users/${u}?$select=accountEnabled`, { headers: h }); return { provider: 'entra', providerConfirmed: c.json?.accountEnabled === true, detail: `Entra accountEnabled=${c.json?.accountEnabled}` };
  },
};

// Read-only check: has this user changed their password since `since`? { known, done, detail }. Safe to run in dry-run.
async function checkPasswordChanged(user, since) {
  const name = cfg.connectors.identity;
  try {
    if (name === 'okta') { const o = okta, g = await http('GET', `${o.base()}/api/v1/users/${encodeURIComponent(user)}`, { headers: o.h() }); if (!g.ok) return { known: false, detail: 'Okta HTTP ' + g.status }; const ch = g.json?.passwordChanged; const done = !!ch && Date.parse(ch) > Date.parse(since) && g.json.status !== 'PASSWORD_EXPIRED'; return { known: true, done, detail: done ? `Okta shows a new password set ${ch}` : `Okta status ${g.json?.status}, password last changed ${ch || 'never'}` }; }
    if (name === 'entra') { const h = { Authorization: 'Bearer ' + await entra.token() }, g = await http('GET', `${entra.graph()}/v1.0/users/${encodeURIComponent(user)}?$select=lastPasswordChangeDateTime`, { headers: h }); if (!g.ok) return { known: false, detail: 'Graph HTTP ' + g.status }; const ch = g.json?.lastPasswordChangeDateTime; const done = !!ch && Date.parse(ch) > Date.parse(since); return { known: true, done, detail: done ? `Entra shows a password change at ${ch}` : `Entra: last password change ${ch || 'unknown'}` }; }
  } catch (e) { return { known: false, detail: e.message }; }
  return { known: false, detail: 'no identity connector (Okta or Entra) is configured, so I cannot verify this myself' };
}
const ADAPTERS = { webhook, okta, entra };
const domainOf = (type) => DOMAIN[type] || null;
const nameFor = (type) => cfg.connectors[DOMAIN[type]] || 'none';
const adapterFor = (type) => ADAPTERS[nameFor(type)] || null;
function status() { return Object.fromEntries(Object.entries(cfg.connectors).map(([d, n]) => [d, n === 'sim' ? 'simulator' : n === 'none' ? 'not connected (manual)' : `${n}${cfg.connectorDryRun ? ' (DRY-RUN)' : ' (LIVE)'}`])); }
module.exports = { checkPasswordChanged, domainOf, nameFor, adapterFor, status, ADAPTERS, DOMAIN };
