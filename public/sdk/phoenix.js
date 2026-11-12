'use strict';
/*  PHOENIX X SDK: one file, zero dependencies (Node 18+, Next.js, Vercel/Netlify/Cloudflare-style runtimes with fetch).
 *  Reports web errors and login events from YOUR app to PHOENIX X so it can detect scanning, credential stuffing and abuse.
 *  Never throws, never blocks a response. Create a connection in PHOENIX X -> Connect a platform to get a key.
 *
 *    const { createPhoenix } = require('./phoenix');
 *    const phx = createPhoenix({ url: 'https://phoenix.example.com', key: process.env.PHOENIX_KEY });
 *    app.use(phx.middleware());                       // Express / Connect / Fastify(middie)
 *    phx.loginFailed({ user: email, ip });            // in your auth code
 */
const AUTH_PATH = /^\/(api\/)?(auth|login|signin|sign-in|session|token|oauth|wp-login\.php|users\/sign_in|admin\/login)(\/|\?|$)/i;

function createPhoenix(opts = {}) {
  const cfg = {
    url: String(opts.url || '').replace(/\/$/, ''), key: opts.key, source: opts.source || 'sdk',
    report: opts.report || 'errors',          // 'errors' (status >= 400, default) | 'all'
    includeQuery: !!opts.includeQuery,        // query strings can hold tokens: off by default; turn on to detect injection in URLs
    flushMs: opts.flushMs ?? 2000, maxBatch: opts.maxBatch || 50, timeoutMs: opts.timeoutMs || 4000, onError: opts.onError || (() => {}),
    immediate: opts.immediate ?? !!(typeof process !== 'undefined' && process.env && (process.env.VERCEL || process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME)),
    trustProxy: opts.trustProxy ?? true,
  };
  let q = [], timer = null, inflight = Promise.resolve();
  const enabled = () => !!(cfg.url && cfg.key);

  function send(events) {
    if (!events.length || !enabled()) return Promise.resolve();
    return fetch(cfg.url + '/api/ingest', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': cfg.key }, body: JSON.stringify({ events }), keepalive: true, signal: AbortSignal.timeout(cfg.timeoutMs) })
      .then((r) => { if (!r.ok) cfg.onError(new Error('PHOENIX responded ' + r.status)); }).catch((e) => cfg.onError(e));
  }
  function flush() { clearTimeout(timer); timer = null; const batch = q; q = []; inflight = inflight.then(() => send(batch)); return inflight; }
  function track(ev) {
    try {
      if (!enabled()) return; q.push({ ts: new Date().toISOString(), ...ev });
      if (cfg.immediate || q.length >= cfg.maxBatch) return void flush();
      if (!timer && cfg.flushMs > 0) { timer = setTimeout(flush, cfg.flushMs); if (timer.unref) timer.unref(); }
    } catch (e) { cfg.onError(e); }
  }

  const hdr = (req, n) => (req.headers && typeof req.headers.get === 'function' ? req.headers.get(n) : req.headers && req.headers[n]) || '';
  function ipOf(req) {
    for (const h of ['cf-connecting-ip', 'x-vercel-forwarded-for', 'x-real-ip', 'x-forwarded-for']) { const v = hdr(req, h); if (v && cfg.trustProxy) return String(v).split(',')[0].trim(); }
    return req.ip || (req.socket && req.socket.remoteAddress) || undefined;
  }
  function record(req, status, extra = {}) {
    try {
      const raw = req.originalUrl || req.url || ''; let path = raw; let host = hdr(req, 'host');
      if (/^https?:\/\//i.test(raw)) { const u = new URL(raw); path = u.pathname + u.search; host = host || u.host; }
      if (!cfg.includeQuery) path = path.split('?')[0]; path = path.slice(0, 300);
      status = Number(status) || 0; if (cfg.report === 'errors' && status > 0 && status < 400) return;
      const ip = ipOf(req); if (!ip) return; const method = req.method || 'GET'; const country = hdr(req, 'x-vercel-ip-country') || hdr(req, 'cf-ipcountry') || undefined;
      const base = { ip, host, resource: path, geo: country ? { country } : undefined };
      track({ ...base, source: 'network', type: 'web_request', outcome: status >= 400 ? 'failure' : 'success', details: { platform: cfg.source, method, status, userAgent: String(hdr(req, 'user-agent')).slice(0, 160), ...extra } });
      if ((status === 401 || status === 403) && method.toUpperCase() === 'POST' && AUTH_PATH.test(path.split('?')[0])) track({ ...base, source: 'authentication', type: 'login_failed', outcome: 'failure', details: { platform: cfg.source, via: 'http-status', status } });
    } catch (e) { cfg.onError(e); }
  }

  return {
    track, flush, record,
    /** Express/Connect middleware. */
    middleware() { return (req, res, next) => { try { res.on('finish', () => record(req, res.statusCode)); } catch (e) { cfg.onError(e); } next(); }; },
    /** Wrap a Next.js App Router route handler or any (Request) => Response function. */
    withPhoenix(handler) { return async (req, ...rest) => { try { const res = await handler(req, ...rest); record(req, res && res.status); return res; } catch (e) { record(req, 500); throw e; } }; },
    loginFailed({ user, ip, country, reason } = {}) { track({ source: 'authentication', type: 'login_failed', outcome: 'failure', user, ip, geo: country ? { country } : undefined, details: { platform: cfg.source, reason } }); },
    loginSucceeded({ user, ip, country, device } = {}) { track({ source: 'authentication', type: 'login_success', outcome: 'success', user, ip, device, geo: country ? { country } : undefined, details: { platform: cfg.source } }); },
    /** Report a privileged/config change in your own app (role granted, API key created, data exported ...). */
    change({ what, actor, resource, change = 'config_change' } = {}) { track({ source: 'application', type: 'platform_change', resource, outcome: 'success', details: { platform: cfg.source, change, what, actor } }); },
  };
}
if (typeof module !== 'undefined' && module.exports) module.exports = { createPhoenix };
if (typeof globalThis !== 'undefined') globalThis.createPhoenix = globalThis.createPhoenix || createPhoenix;
