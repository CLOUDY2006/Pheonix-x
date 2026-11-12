'use strict';
// SQLite via Node's built-in node:sqlite (no npm packages): WAL, versioned migrations, write-behind batching.
// Exposes (1) low-level helpers (get/tx/kv/backup) used by auth, registry, ingest keys, suppressions and
// (2) the persistence facade used by persist.js (init -> loadAudit/saveEvent/saveIncident/...).
const fs = require('fs');
const path = require('path');
const cfg = require('./config');
const { DatabaseSync } = require('node:sqlite');

let db = null, curFile = null, facade = null, evQueue = [], evTimer = null; const incTimers = new Map(); const incLatest = new Map();
const MIGRATIONS = [
  `create table events(id text primary key, ts text not null, origin text not null, json text not null);
   create index ix_events_ts on events(ts);
   create table incidents(id text primary key, json text not null, updated_at text not null);
   create table audit(seq integer primary key, json text not null);
   create table users(username text primary key, role text not null check(role in ('viewer','analyst','admin')), salt text not null, hash text not null, disabled integer default 0, totp_secret text, totp_enabled integer default 0, created_at text not null, last_login text, must_change integer default 0);
   create table sessions(id_hash text primary key, username text not null, csrf text not null, created_at integer not null, expires_at integer not null, last_seen integer not null, ip text, ua text);
   create table ingest_keys(id text primary key, name text not null, hash text unique not null, format text default 'generic', created_at text not null, last_used text, disabled integer default 0);
   create table suppressions(id text primary key, rule text not null, user text, ip text, host text, reason text not null, created_by text not null, created_at text not null, expires_at text);
   create table profiles(user text primary key, json text not null);
   create table assets(kind text not null, name text not null, json text not null, primary key(kind,name));
   create table backups(id text primary key, host text not null, json text not null);
   create table tickets(id text primary key, json text not null);
   create table outbox(id text primary key, json text not null);
   create table kv(key text primary key, value text not null);`,
  // v2: per-key settings (signing secret, verify token) and a received-event counter for the "connect a platform" wizard
  `alter table ingest_keys add column meta text default '{}'; alter table ingest_keys add column received integer default 0;`,
  // v3: pull collectors (API tokens are stored encrypted, never in clear text)
  `create table collectors(id text primary key, platform text not null, name text not null, token_enc text not null, config text default '{}', interval_sec integer default 120, enabled integer default 1, cursor text default '{}', last_run text, last_status text, last_error text, total_events integer default 0, created_by text, created_at text not null);`,
  // v4: application resilience (dependency graph, readiness checks, runs, incident memory)
  `create table rz_nodes(id text primary key, type text not null, provider text, name text not null, meta text default '{}', source text, confidence text default 'declared', updated_at text);
   create table rz_edges(id text primary key, src text not null, dst text not null, kind text not null, confidence text default 'declared', evidence text, source text);
   create index rz_edges_src on rz_edges(src); create index rz_edges_dst on rz_edges(dst);
   create table rz_checks(id text primary key, node text, name text not null, type text not null, config text default '{}', secret_enc text, required integer default 1, created_by text, created_at text);
   create table rz_runs(id text primary key, kind text not null, ref text, status text, result text, by text, at text);
   create table rz_memory(id text primary key, incident text, sig text, record text, at text);
   alter table collectors add column write_enabled integer default 0;`,
  // v5: chat channels (Telegram / Slack / Discord / email). Config (tokens, signing secrets) is stored encrypted.
  `create table channels(id text primary key, kind text not null, name text not null, config_enc text not null, allow text default '[]', role text default 'analyst', min_severity text default 'high', enabled integer default 1, cursor text default '{}', pair_code text, pair_exp text, last_status text, last_error text, last_run text, created_by text, created_at text not null);`,
];
function open(file = cfg.dbPath) {
  if (db && file === curFile) return db;
  if (db) close();
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  db = new DatabaseSync(file); curFile = file;
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
  const v = db.prepare('PRAGMA user_version').get().user_version;
  for (let i = v; i < MIGRATIONS.length; i++) { db.exec('BEGIN'); try { db.exec(MIGRATIONS[i]); db.exec(`PRAGMA user_version=${i + 1}`); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; } }
  return db;
}
const get = () => db || open();
const tx = (fn) => { const d = get(); d.exec('BEGIN'); try { const r = fn(d); d.exec('COMMIT'); return r; } catch (e) { d.exec('ROLLBACK'); throw e; } };
const kvGet = (k, d = null) => { const r = get().prepare('select value from kv where key=?').get(k); return r ? JSON.parse(r.value) : d; };
const kvSet = (k, v) => get().prepare('insert into kv(key,value) values(?,?) on conflict(key) do update set value=excluded.value').run(k, JSON.stringify(v));
const J = (o) => JSON.stringify(o);

function flush() {
  clearTimeout(evTimer); evTimer = null;
  if (evQueue.length) { const q = evQueue; evQueue = []; try { tx((d) => { const st = d.prepare('insert or ignore into events(id,ts,origin,json) values(?,?,?,?)'); for (const e of q) st.run(e.id, e.ts, e.origin, J(e)); }); } catch (e) { process.stderr.write('event persist failed: ' + e.message + '\n'); } }
  for (const [id, t] of incTimers) { clearTimeout(t); incTimers.delete(id); writeIncident(incLatest.get(id)); }
}
function writeIncident(i) { if (!i) return; get().prepare('insert into incidents(id,json,updated_at) values(?,?,?) on conflict(id) do update set json=excluded.json, updated_at=excluded.updated_at').run(i.id, J(i), new Date().toISOString()); }

// ---- persistence facade (used by persist.js) ----
function init(file = cfg.dbPath) {
  open(file);
  facade = {
    loadAudit: () => get().prepare('select json from audit order by seq').all().map((r) => JSON.parse(r.json)),
    loadEvents: (n = 5000) => get().prepare('select json from events order by ts desc limit ?').all(n).map((r) => JSON.parse(r.json)).reverse(),
    loadIncidents: () => get().prepare('select json from incidents order by id').all().map((r) => JSON.parse(r.json)),
    saveAudit: (a) => get().prepare('insert or ignore into audit(seq,json) values(?,?)').run(a.seq, J(a)),
    saveEvent: (e) => { evQueue.push(e); if (evQueue.length >= 500) flush(); else if (!evTimer) { evTimer = setTimeout(flush, 250); evTimer.unref?.(); } },
    saveIncident: (i) => { incLatest.set(i.id, i); if (!incTimers.has(i.id)) { const t = setTimeout(() => { incTimers.delete(i.id); writeIncident(incLatest.get(i.id)); }, 400); t.unref?.(); incTimers.set(i.id, t); } },
    prune: (days = cfg.retentionDays) => get().prepare('delete from events where ts < ?').run(new Date(Date.now() - days * 864e5).toISOString()).changes,
    flush, close,
  };
  return facade;
}
function backup(dest) { flush(); const f = dest || path.join(cfg.backupDir, `phoenix-${new Date().toISOString().replace(/[:.]/g, '-')}.db`); fs.mkdirSync(path.dirname(f), { recursive: true }); get().prepare('VACUUM INTO ?').run(f); return f; }
function close() { if (!db) return; try { flush(); } catch {} try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch {} db.close(); db = null; curFile = null; facade = null; }
module.exports = { open, init, get, tx, kvGet, kvSet, backup, close, flush, wipeDemoData() { for (const t of ['events', 'incidents', 'tickets', 'outbox']) get().exec(`delete from ${t}`); }, get active() { return !!db; }, api: { close, backup, flush } };
