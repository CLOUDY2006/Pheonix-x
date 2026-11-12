'use strict';
// AUTONOMY — how much the AI is allowed to do on its own. One policy, three modes, always reversible, always audited.
//   watch     AI detects, investigates, correlates and RECOMMENDS. A human approves every action. (read-only / advisory)
//   balanced  AI acts alone on reversible, low-blast-radius actions: block IPs, revoke sessions/tokens, restrict a
//             resource, suspend a suspicious account. Cautious ones (isolate host, cloud policy, public bucket,
//             production assets) wait for a human.
//   full      AI also does the cautious ones. It recovers on its own (auto-unblock after a quiet period).
// In EVERY mode: restricted actions (delete data, shut down/wipe hosts, change security controls) are never executed;
// protected entities always need a human; and an hourly action budget (circuit breaker) falls back to approval.
const db = require('./db');
const audit = require('./audit');
const cfg = require('./config');

const MODES = {
  watch: { label: 'Watch', blurb: 'AI watches, investigates and recommends. Humans approve every action.' },
  balanced: { label: 'Balanced', blurb: 'AI blocks and revokes on its own (IPs, sessions, tokens, suspicious accounts). Cautious actions wait for you.' },
  full: { label: 'Full AI', blurb: 'AI handles everything it is allowed to, and un-does its own blocks once things are quiet. Destructive actions are still never run.' },
};
const AUTO_BY_MODE = {
  watch: new Set(),
  balanced: new Set(['block_ip', 'force_password_reset', 'revoke_sessions', 'revoke_token', 'restrict_resource', 'disable_account']),
  full: new Set(['block_ip', 'force_password_reset', 'revoke_sessions', 'revoke_token', 'restrict_resource', 'disable_account', 'isolate_host', 'detach_cloud_policy', 'make_bucket_private']),
};
// how long the AI's own containment stays before it is lifted automatically (hours). null = stays until a human lifts it.
const TTL_H = { block_ip: 24, restrict_resource: 24, disable_account: 24, isolate_host: 24, detach_cloud_policy: null, make_bucket_private: null };
// which modes may lift which action automatically
const AUTO_LIFT = { balanced: new Set(['block_ip', 'restrict_resource']), full: new Set(['block_ip', 'restrict_resource', 'disable_account', 'isolate_host']) };

const budgetMax = () => Math.max(1, +process.env.PHOENIX_AI_ACTION_BUDGET || 25);
let mode = (cfg.autonomy && MODES[cfg.autonomy]) ? cfg.autonomy : (cfg.isProd ? 'watch' : 'balanced');
let prot = []; // [{id, kind:'user'|'ip'|'host'|'resource', value, reason, by, at, expiresAt|null}]
let stamps = []; // timestamps of AI auto actions (rolling hour)
let tripped = null;

function load() {
  try { const s = db.kvGet('autonomy', null); if (s && MODES[s.mode]) mode = s.mode; const p = db.kvGet('protected', null); if (Array.isArray(p)) prot = p; } catch { /* first boot */ }
}
const save = () => { try { db.kvSet('autonomy', { mode }); db.kvSet('protected', prot); } catch { /* best effort */ } };
const getMode = () => mode;
function setMode(m, by = 'system', { silent = false } = {}) {
  if (!MODES[m]) throw new Error('mode must be watch, balanced or full');
  const prev = mode; mode = m; tripped = null; save();
  if (!silent) audit.log(by, 'AUTONOMY_CHANGED', { from: prev, to: m });
  return mode;
}

const isPrivateIp = (ip) => /^(10\.|192\.168\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd)/i.test(ip || '');
const live = () => { const n = Date.now(); const before = prot.length; prot = prot.filter((p) => !p.expiresAt || Date.parse(p.expiresAt) > n); if (prot.length !== before) save(); return prot; };
function isProtected(target = {}) {
  const checks = [['user', target.user], ['ip', target.ip], ['host', target.host], ['resource', target.resource]].filter((x) => x[1]);
  for (const [k, v] of checks) { if (k === 'ip' && isPrivateIp(v)) return { reason: 'private/internal address' }; const p = live().find((x) => x.kind === k && x.value === v); if (p) return { reason: p.reason || 'protected entity', entry: p }; }
  return null;
}
function protect({ kind, value, reason, hours = null }, by) {
  if (!['user', 'ip', 'host', 'resource'].includes(kind)) throw new Error('kind must be user, ip, host or resource');
  if (!value || String(value).length > 200) throw new Error('value required');
  if (!reason || String(reason).length < 3) throw new Error('reason required');
  const ex = prot.find((p) => p.kind === kind && p.value === value); if (ex) prot = prot.filter((p) => p !== ex);
  const e = { id: 'prt-' + Math.random().toString(36).slice(2, 9), kind, value: String(value), reason: String(reason).slice(0, 200), by, at: new Date().toISOString(), expiresAt: hours ? new Date(Date.now() + hours * 3600e3).toISOString() : null };
  prot.push(e); save(); audit.log(by, 'PROTECTED_ADDED', e); return e;
}
function unprotect(id, by) { const e = prot.find((p) => p.id === id); prot = prot.filter((p) => p.id !== id); save(); if (e) audit.log(by, 'PROTECTED_REMOVED', e); }
const listProtected = () => live().slice();

const used = () => { const c = Date.now() - 3600e3; stamps = stamps.filter((t) => t > c); return stamps.length; };
function spend() {
  stamps.push(Date.now());
  if (used() >= budgetMax() && !tripped) { tripped = new Date().toISOString(); audit.log('GUARDIAN', 'AI_BUDGET_EXHAUSTED', { budget: budgetMax(), note: 'circuit breaker: further actions this hour need approval' }); }
}
const status = () => ({ mode, modes: MODES, budget: { max: budgetMax(), used: used(), tripped: used() >= budgetMax() }, protectedCount: live().length, ttl: TTL_H });

// Decide the tier for a (catalogTier, type, target). Returns {tier, why, auto:boolean}
function decide(type, catTier, target = {}, { ignoreBudget = false, assetEnv = null, forceWatch = false } = {}) {
  if (catTier === 'restricted') return { tier: 'restricted', why: 'Destructive / security-control action: never executed by the AI in any mode' };
  const m = forceWatch ? 'watch' : mode;
  if (!AUTO_BY_MODE[m].has(type)) return { tier: 'approval', why: m === 'watch' ? 'Watch mode: AI recommends, a human approves' : `${MODES[m].label} mode: this action is high-impact, so a human approves` };
  const p = isProtected(target); if (p) return { tier: 'approval', why: `Protected entity (${p.reason}): needs a human` };
  if (assetEnv === 'production' && m !== 'full') return { tier: 'approval', why: `${MODES[m].label} mode: target is a PRODUCTION asset, so a human approves` };
  if (!ignoreBudget && used() >= budgetMax()) return { tier: 'approval', why: `Circuit breaker: AI already took ${used()} actions this hour (limit ${budgetMax()})` };
  return { tier: 'automatic', why: `AI acted alone (${MODES[m].label} mode): reversible, you can unblock it`, auto: true };
}
const ttlFor = (type) => TTL_H[type] ?? null;
const canAutoLift = (type) => !!AUTO_LIFT[mode]?.has(type);
const reset = () => { prot = []; stamps = []; tripped = null; };
module.exports = { reset, MODES, load, getMode, setMode, status, decide, spend, protect, unprotect, listProtected, isProtected, isPrivateIp, ttlFor, canAutoLift };
