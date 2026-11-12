'use strict';
// Asset & identity registry. In demo mode it is seeded by the simulator; in production it is built from
// real events (user baselines are LEARNED, never assumed) and from assets you register via the API.
const db = require('./db');
const cfg = require('./config');
const sim = require('../sim/enterprise');
const audit = require('./audit');

const LEARN_AFTER = +process.env.PHOENIX_BASELINE_LOGINS || 3;
const timers = new Map();
const newUser = (name) => ({ dept: null, role: 'unknown', homeGeo: null, devices: [], env: cfg.isProd ? 'production' : 'sandbox', status: 'active', mfa: null, sessions: [], tokens: [], learned: false, logins: 0, geoCounts: {}, firstSeen: new Date().toISOString(), externalIds: {}, _auto: true });

// Existing profile, or (for real/ingested data and production mode) a fresh one in "learning" state.
function userFor(e) {
  if (!e.user) return null; const u = sim.env.users[e.user]; if (u) return u;
  if (!cfg.isProd && e.origin !== 'ingested') return null; // demo simulations never invent users
  const p = sim.env.users[e.user] = newUser(e.user); save(e.user); audit.log('REGISTRY', 'USER_DISCOVERED', { user: e.user, note: 'baseline learning started' }); return p;
}
// Learn only from CLEAN logins so an attacker cannot poison a baseline.
function learn(u, e) {
  if (!u || !u._auto && u.learned) return; u.logins = (u.logins || 0) + 1;
  if (e.geo) u.geoCounts[e.geo] = (u.geoCounts[e.geo] || 0) + 1;
  if (e.device && !u.devices.includes(e.device) && u.devices.length < 10) u.devices.push(e.device);
  if (typeof e.details?.mfa === 'boolean' && u.mfa !== true) u.mfa = e.details.mfa;
  if (!u.homeGeo && u.logins >= LEARN_AFTER) { const top = Object.entries(u.geoCounts).sort((a, b) => b[1] - a[1])[0]; if (top) { u.homeGeo = top[0]; u.learned = true; audit.log('REGISTRY', 'BASELINE_LEARNED', { user: e.user, homeGeo: u.homeGeo, devices: u.devices }); } }
  save(e.user);
}
function save(name) {
  if (!sim.env.users[name]?._auto || timers.has(name)) return;
  timers.set(name, setTimeout(() => { timers.delete(name); if (!db.active) return; try { db.get().prepare('insert or replace into profiles(user,json) values(?,?)').run(name, JSON.stringify(sim.env.users[name])); } catch {} }, 1000).unref?.());
}
function loadProduction() {
  if (!cfg.isProd) return;
  const d = db.get();
  for (const r of d.prepare('select user,json from profiles').all()) sim.env.users[r.user] = JSON.parse(r.json);
  for (const r of d.prepare('select kind,name,json from assets').all()) { const j = JSON.parse(r.json); if (r.kind === 'host') sim.env.hosts[r.name] = { isolated: false, status: 'online', ...j }; else if (r.kind === 'resource') sim.env.resources[r.name] = { restricted: false, ...j }; else if (r.kind === 'user') sim.env.users[r.name] = { ...(sim.env.users[r.name] || newUser(r.name)), ...j, _auto: false }; }
  for (const r of d.prepare('select host,json from backups').all()) (sim.env.backups[r.host] ||= []).push(JSON.parse(r.json));
}
const KINDS = { host: ['kind', 'role', 'env', 'criticality', 'owner'], resource: ['owner', 'sensitivity', 'env'], user: ['dept', 'role', 'homeGeo', 'devices', 'mfa', 'env', 'externalIds'] };
function upsertAsset(kind, name, body) {
  if (!KINDS[kind]) throw new Error('kind must be host|resource|user'); if (!/^[\w./:@-]{1,120}$/.test(name)) throw new Error('invalid name');
  const clean = {}; for (const k of KINDS[kind]) if (body[k] !== undefined) clean[k] = body[k];
  if (clean.env && !['sandbox', 'production'].includes(clean.env)) throw new Error('env must be sandbox|production');
  if (clean.criticality && !['low', 'medium', 'high', 'critical'].includes(clean.criticality)) throw new Error('invalid criticality');
  const target = kind === 'host' ? 'hosts' : kind === 'resource' ? 'resources' : 'users';
  const cur = sim.env[target][name] || (kind === 'user' ? newUser(name) : {}); Object.assign(cur, { ...(kind === 'host' ? { isolated: false, status: 'online' } : {}), env: 'production' }, cur, clean); if (kind === 'user') cur._auto = false; sim.env[target][name] = cur;
  db.get().prepare('insert or replace into assets(kind,name,json) values(?,?,?)').run(kind, name, JSON.stringify(Object.fromEntries(Object.entries(cur).filter(([k]) => !['sessions', 'tokens', 'isolated', 'status', 'restricted'].includes(k)))));
  audit.log('REGISTRY', 'ASSET_UPSERT', { kind, name, ...clean }); return cur;
}
function addBackup(host, b) {
  if (!host || !b?.id || !b.ts) throw new Error('host, id and ts required'); const rec = { id: String(b.id), ts: new Date(b.ts).toISOString(), verified: !!b.verified, immutable: !!b.immutable, sizeGB: +b.sizeGB || 0 };
  (sim.env.backups[host] ||= []).push(rec); db.get().prepare('insert or replace into backups(id,host,json) values(?,?,?)').run(rec.id, host, JSON.stringify(rec)); audit.log('REGISTRY', 'BACKUP_RECORDED', { host, ...rec }); return rec;
}
module.exports = { userFor, learn, loadProduction, upsertAsset, addBackup, LEARN_AFTER };
