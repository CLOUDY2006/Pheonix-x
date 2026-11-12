'use strict';
// Authentication & RBAC backed by the database.
//  - Passwords: scrypt (per-user salt), minimum 12 characters, must contain letters and digits.
//  - Sessions: random 256-bit token; only its SHA-256 is stored. Delivered as an HttpOnly SameSite=Strict cookie
//    (browser) or usable as a Bearer token (scripts). Absolute + idle expiry. State-changing cookie requests need the CSRF header.
//  - Lockout: 5 failed logins per account (or 20 per IP) within 15 minutes => locked until the window passes.
//  - Optional TOTP (RFC 6238, SHA-1, 6 digits, 30 s) per user; can be required for admins.
//  - Ingest API keys: random, stored hashed, shown once, individually revocable.
const crypto = require('crypto');
const dbm = require('./db');
const cfg = require('./config');
const audit = require('./audit');

const DEMO_PW = 'phoenix-demo';
const RANK = { viewer: 1, analyst: 2, admin: 3 };
const ROLES = Object.keys(RANK);
const NAME = /^[a-zA-Z0-9._@-]{3,64}$/;
const now = () => Date.now();
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
const G = () => dbm.get();

function policyError(pw, username = '') {
  if (typeof pw !== 'string' || pw.length < 12) return 'password must be at least 12 characters';
  if (pw.length > 200) return 'password too long';
  if (!/[a-zA-Z]/.test(pw) || !/[0-9]/.test(pw)) return 'password must contain letters and digits';
  if (username && pw.toLowerCase().includes(username.toLowerCase())) return 'password must not contain the username';
  return null;
}

// ---------- users ----------
const pub = (u) => u && { username: u.username, role: u.role, disabled: !!u.disabled, totp: !!u.totp_enabled, createdAt: u.created_at, lastLogin: u.last_login, mustChange: !!u.must_change };
const row = (n) => G().prepare('select * from users where username=?').get(n);
function count() { return G().prepare('select count(*) c from users').get().c; }
function createUser({ username, password, role = 'analyst', mustChange = false, skipPolicy = false }, by = 'SYSTEM') {
  if (!NAME.test(username || '')) throw new Error('username must be 3-64 chars: letters, digits . _ @ -');
  if (!ROLES.includes(role)) throw new Error('invalid role');
  const pe = skipPolicy ? null : policyError(password, username); if (pe) throw new Error(pe);
  if (row(username)) throw new Error('user already exists');
  const salt = crypto.randomBytes(16).toString('hex');
  G().prepare('insert into users(username,role,salt,hash,created_at,must_change) values(?,?,?,?,?,?)').run(username, role, salt, scrypt(password, salt), new Date().toISOString(), mustChange ? 1 : 0);
  audit.log(by, 'USER_CREATED', { username, role });
  return pub(row(username));
}
function listUsers() { return G().prepare('select * from users order by username').all().map(pub); }
function adminsLeft(except) { return G().prepare("select count(*) c from users where role='admin' and disabled=0 and username<>?").get(except || '').c; }
function updateUser(username, patch, by) {
  const u = row(username); if (!u) throw new Error('no such user');
  if (patch.role !== undefined) { if (!ROLES.includes(patch.role)) throw new Error('invalid role'); if (u.role === 'admin' && patch.role !== 'admin' && !adminsLeft(username)) throw new Error('cannot remove the last admin'); G().prepare('update users set role=? where username=?').run(patch.role, username); }
  if (patch.disabled !== undefined) { if (patch.disabled && u.role === 'admin' && !adminsLeft(username)) throw new Error('cannot disable the last admin'); G().prepare('update users set disabled=? where username=?').run(patch.disabled ? 1 : 0, username); if (patch.disabled) revokeAll(username); }
  if (patch.password !== undefined) { const pe = policyError(patch.password, username); if (pe) throw new Error(pe); const salt = crypto.randomBytes(16).toString('hex'); G().prepare('update users set salt=?,hash=?,must_change=0 where username=?').run(salt, scrypt(patch.password, salt), username); revokeAll(username); }
  audit.log(by, 'USER_UPDATED', { username, fields: Object.keys(patch).map((k) => (k === 'password' ? 'password' : k + '=' + patch[k])) });
  return pub(row(username));
}
function deleteUser(username, by) { const u = row(username); if (!u) throw new Error('no such user'); if (u.role === 'admin' && !adminsLeft(username)) throw new Error('cannot delete the last admin'); revokeAll(username); G().prepare('delete from users where username=?').run(username); audit.log(by, 'USER_DELETED', { username }); }
function changePassword(username, oldPw, newPw) {
  const u = row(username); if (!u || !checkPw(u, oldPw)) throw new Error('current password is incorrect');
  const pe = policyError(newPw, username); if (pe) throw new Error(pe);
  const salt = crypto.randomBytes(16).toString('hex'); G().prepare('update users set salt=?,hash=?,must_change=0 where username=?').run(salt, scrypt(newPw, salt), username);
  revokeAll(username); audit.log(username, 'PASSWORD_CHANGED', {});
}
function checkPw(u, pw) { if (typeof pw !== 'string') return false; const a = Buffer.from(scrypt(pw, u.salt)), b = Buffer.from(u.hash); return a.length === b.length && crypto.timingSafeEqual(a, b); }
const needsSetup = () => cfg.isProd && count() === 0;
function seedDemo() {
  if (!cfg.seedDemoUsers || count() > 0) return false;
  const E = process.env;
  for (const [n, r, k] of [['admin', 'admin', 'PHOENIX_ADMIN_PASSWORD'], ['analyst', 'analyst', 'PHOENIX_ANALYST_PASSWORD'], ['viewer', 'viewer', 'PHOENIX_VIEWER_PASSWORD']]) createUser({ username: n, password: E[k] || DEMO_PW, role: r, skipPolicy: true }, 'SYSTEM');
  return true;
}
const demoCreds = () => { try { return cfg.seedDemoUsers && ['admin', 'analyst', 'viewer'].some((n) => { const u = row(n); return u && checkPw(u, DEMO_PW); }); } catch { return false; } };
function firstAdmin({ username, password, setupToken }, ip) {
  if (count() > 0) throw new Error('setup already completed');
  if (cfg.setupToken && setupToken !== cfg.setupToken) { audit.log('AUTH', 'SETUP_DENIED', { ip }); throw new Error('invalid setup token'); }
  const u = createUser({ username, password, role: 'admin' }, 'SETUP'); audit.log('SETUP', 'FIRST_ADMIN_CREATED', { username, ip }); return u;
}

// ---------- TOTP ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = (buf) => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
const b32dec = (s) => { let bits = ''; for (const c of s.replace(/=+$/, '').toUpperCase()) { const v = B32.indexOf(c); if (v < 0) throw new Error('bad base32'); bits += v.toString(2).padStart(5, '0'); } const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
function totpAt(secret, t = now()) { const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(t / 30000))); const h = crypto.createHmac('sha1', b32dec(secret)).update(c).digest(); const o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); }
const totpOk = (secret, code, t = now()) => /^\d{6}$/.test(String(code || '')) && [-1, 0, 1].some((d) => { const a = Buffer.from(totpAt(secret, t + d * 30000)), b = Buffer.from(String(code)); return crypto.timingSafeEqual(a, b); });
function totpBegin(username) { const u = row(username); if (!u) throw new Error('no such user'); const s = b32enc(crypto.randomBytes(20)); G().prepare('update users set totp_secret=?,totp_enabled=0 where username=?').run(s, username); return { secret: s, uri: `otpauth://totp/Phoenix%20X:${encodeURIComponent(username)}?secret=${s}&issuer=Phoenix%20X&digits=6&period=30` }; }
function totpConfirm(username, code) { const u = row(username); if (!u?.totp_secret || !totpOk(u.totp_secret, code)) throw new Error('invalid code'); G().prepare('update users set totp_enabled=1 where username=?').run(username); audit.log(username, 'TOTP_ENABLED', {}); }
function totpDisable(username, by) { G().prepare('update users set totp_secret=null,totp_enabled=0 where username=?').run(username); audit.log(by, 'TOTP_DISABLED', { username }); }

// ---------- login / sessions ----------
const fails = new Map(); // key -> [timestamps]
const WIN = 15 * 60e3;
const recent = (k) => { const a = (fails.get(k) || []).filter((t) => now() - t < WIN); fails.set(k, a); return a; };
const lockedOut = (user, ip) => recent('u:' + user).length >= 5 || recent('i:' + ip).length >= 20;
const noteFail = (user, ip) => { recent('u:' + user).push(now()); recent('i:' + ip).push(now()); };
const clearFails = (user) => fails.delete('u:' + user);
function resetLockouts() { fails.clear(); }

function login({ username, password, totp }, ctx = {}) {
  const ip = ctx.ip || '?'; username = String(username || '').slice(0, 64);
  if (lockedOut(username, ip)) { audit.log('AUTH', 'LOGIN_LOCKED_OUT', { username, ip }); return { error: 'too many failed attempts; try again in 15 minutes', code: 429 }; }
  const u = row(username);
  // constant-ish time: always run scrypt even for unknown users
  const ok = u ? checkPw(u, password) : (scrypt(String(password || ''), 'x'.repeat(32)), false);
  if (!u || !ok || u.disabled) { noteFail(username, ip); audit.log('AUTH', 'LOGIN_FAILED', { username, ip }); return { error: 'invalid credentials', code: 401 }; }
  if (u.totp_enabled) {
    if (!totp) return { error: 'authentication code required', code: 401, totpRequired: true };
    if (!totpOk(u.totp_secret, totp)) { noteFail(username, ip); audit.log('AUTH', 'LOGIN_FAILED_TOTP', { username, ip }); return { error: 'invalid authentication code', code: 401, totpRequired: true }; }
  } else if (cfg.requireAdminTotp && u.role === 'admin') {
    // admin without TOTP must enrol before getting a full session; give a restricted one (enrol endpoints only)
    return issue(u, ctx, true);
  }
  clearFails(username); return issue(u, ctx, false);
}
function issue(u, ctx, enrolOnly) {
  const token = crypto.randomBytes(32).toString('base64url'), csrf = crypto.randomBytes(18).toString('base64url');
  G().prepare('insert into sessions(id_hash,username,csrf,created_at,expires_at,last_seen,ip,ua) values(?,?,?,?,?,?,?,?)').run(sha(token), u.username, csrf, now(), now() + cfg.sessionHours * 3600e3, now(), ctx.ip || null, String(ctx.ua || '').slice(0, 200));
  G().prepare('update users set last_login=? where username=?').run(new Date().toISOString(), u.username);
  audit.log(u.username, 'LOGIN', { role: u.role, enrolOnly });
  return { token, csrf, user: u.username, role: u.role, mustChange: !!u.must_change, totpEnrolRequired: enrolOnly };
}
function verify(token) {
  if (!token || typeof token !== 'string' || token.length > 200) return null;
  const s = G().prepare('select * from sessions where id_hash=?').get(sha(token)); if (!s) return null;
  if (s.expires_at < now() || now() - s.last_seen > cfg.idleMinutes * 60e3) { G().prepare('delete from sessions where id_hash=?').run(s.id_hash); return null; }
  const u = row(s.username); if (!u || u.disabled) return null;
  if (now() - s.last_seen > 30e3) G().prepare('update sessions set last_seen=? where id_hash=?').run(now(), s.id_hash);
  const enrolOnly = cfg.requireAdminTotp && u.role === 'admin' && !u.totp_enabled;
  return { sub: u.username, role: u.role, csrf: s.csrf, sid: s.id_hash, exp: s.expires_at, mustChange: !!u.must_change, enrolOnly };
}
function logout(token) { if (token) G().prepare('delete from sessions where id_hash=?').run(sha(token)); }
function revokeAll(username) { G().prepare('delete from sessions where username=?').run(username); }
const purgeSessions = () => G().prepare('delete from sessions where expires_at<?').run(now()).changes;
const allowed = (role, min) => (RANK[role] || 0) >= RANK[min];

// ---------- ingest API keys ----------
// A key authenticates one log source / webhook. Accepted as header x-api-key, as HTTP Basic password (Heroku drains),
// or inside the URL path (/api/hook/<key>) for platforms that cannot set headers. Only the SHA-256 is stored.
// Optional per-key meta: signingSecret (verify the platform's HMAC/JWS signature) and verifyToken (Vercel handshake).
const FORMATS = () => require('../ingest/normalize').FORMATS;
function createKey({ name, format = 'generic', signingSecret, verifyToken }, by) {
  if (typeof name !== 'string' || !name.trim() || name.length > 80) throw new Error('name required');
  if (!FORMATS().includes(format)) throw new Error('format must be one of ' + FORMATS().join(', '));
  const meta = {}; if (signingSecret) { if (String(signingSecret).length > 200) throw new Error('signing secret too long'); meta.signingSecret = String(signingSecret); } if (verifyToken) meta.verifyToken = String(verifyToken).slice(0, 200);
  const secret = 'phx_' + crypto.randomBytes(24).toString('base64url'), id = 'key-' + crypto.randomBytes(4).toString('hex');
  G().prepare('insert into ingest_keys(id,name,hash,format,created_at,meta) values(?,?,?,?,?,?)').run(id, name.trim(), sha(secret), format, new Date().toISOString(), JSON.stringify(meta));
  audit.log(by, 'INGEST_KEY_CREATED', { id, name, format, signed: !!meta.signingSecret }); return { id, name, format, key: secret }; // plaintext shown once
}
const listKeys = () => G().prepare('select id,name,format,created_at createdAt,last_used lastUsed,disabled,received,meta from ingest_keys order by created_at').all().map(({ meta, ...k }) => { let m = {}; try { m = JSON.parse(meta || '{}'); } catch { /* ignore */ } return { ...k, signed: !!m.signingSecret, verifyToken: !!m.verifyToken }; });
// One-click rotation: same name/format/signing settings, brand-new secret; the old one stops working immediately.
function rotateKey(id, by) {
  const k = G().prepare('select id,name,format,meta,disabled from ingest_keys where id=?').get(id); if (!k || k.disabled) throw new Error('no such active key');
  let m = {}; try { m = JSON.parse(k.meta || '{}'); } catch { /* ignore */ }
  const n = createKey({ name: k.name, format: k.format, signingSecret: m.signingSecret, verifyToken: m.verifyToken }, by); revokeKey(id, by); audit.log(by, 'INGEST_KEY_ROTATED', { old: id, new: n.id }); return n;
}
function rotateAll(by) { return listKeys().filter((k) => !k.disabled).map((k) => rotateKey(k.id, by)); }
function revokeKey(id, by) { const r = G().prepare('update ingest_keys set disabled=1 where id=?').run(id); if (!r.changes) throw new Error('no such key'); audit.log(by, 'INGEST_KEY_REVOKED', { id }); }
function verifyKey(secret) {
  if (typeof secret !== 'string' || secret.length > 120) return null;
  const k = G().prepare('select id,name,format,meta from ingest_keys where hash=? and disabled=0').get(sha(secret)); if (!k) return null;
  G().prepare('update ingest_keys set last_used=? where id=?').run(new Date().toISOString(), k.id); let meta = {}; try { meta = JSON.parse(k.meta || '{}'); } catch { /* ignore */ } return { id: k.id, name: k.name, format: k.format, meta };
}
const keyById = (id) => G().prepare('select id,name,format,disabled from ingest_keys where id=?').get(id);
const touchKey = (id, n) => G().prepare('update ingest_keys set received=coalesce(received,0)+? where id=?').run(n, id);

module.exports = { rotateAll, login, verify, logout, allowed, demoCreds, DEMO_PW, createUser, listUsers, updateUser, deleteUser, changePassword, needsSetup, seedDemo, firstAdmin, count, policyError, totpBegin, totpConfirm, totpDisable, totpAt, totpOk, createKey, listKeys, revokeKey, rotateKey, verifyKey, keyById, touchKey, purgeSessions, revokeAll, resetLockouts, ROLES, get FORMATS() { return FORMATS(); } };
