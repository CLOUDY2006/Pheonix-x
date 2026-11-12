'use strict';
// Wires the database to the in-memory runtime: restore on boot, write-behind on change.
const bus = require('./bus');
const audit = require('./audit');
const events = require('./events');
const cmd = require('../agents/commander');
const dbm = require('./db');
const sim = require('../sim/enterprise');
const registry = require('./registry');
const suppress = require('./suppressions');
const cfg = require('./config');

let handlers = [], pruneTimer = null;
function stop() { for (const [ev, fn] of handlers) bus.off(ev, fn); handlers = []; clearInterval(pruneTimer); audit.setSink(null); if (dbm.active) dbm.api.close(); }
const safe = (fn) => { try { fn(); } catch { /* never let persistence break the runtime */ } };
function start(file, { retentionDays = 30 } = {}) {
  const db = dbm.init(file);
  const log = audit.load(db.loadAudit());
  if (!log.ok) { console.error(`[persist] AUDIT CHAIN BROKEN at entry ${log.brokenAt} — database may have been tampered with`); }
  audit.setSink(db.saveAudit); // attach BEFORE anything below can log, or those entries would never be stored (chain gap)
  events.load(db.loadEvents(5000));
  const r = cmd.restore(db.loadIncidents());
  const g = dbm.get();
  safe(() => { sim.env.tickets.length = 0; sim.env.tickets.push(...g.prepare('select json from tickets').all().map((x) => JSON.parse(x.json))); sim.env.outbox.length = 0; sim.env.outbox.push(...g.prepare('select json from outbox').all().map((x) => JSON.parse(x.json))); });
  safe(() => { const saved = dbm.kvGet('settings', null); if (saved) { if (Number.isFinite(saved.paceMs)) cmd.settings.paceMs = saved.paceMs; if (typeof saved.autopilot === 'boolean' && !cfg.isProd) cmd.settings.autopilot = saved.autopilot; } });
  safe(() => registry.loadProduction()); safe(() => suppress.load());
  const onEv = (e) => db.saveEvent(e), onInc = (i) => db.saveIncident(cmd.incidents.get(i.id) || i);
  const onNtf = (n) => safe(() => g.prepare('insert or replace into outbox(id,json) values(?,?)').run(n.id, JSON.stringify(n)));
  const onTk = (t) => safe(() => g.prepare('insert or replace into tickets(id,json) values(?,?)').run(t.id, JSON.stringify(t)));
  bus.on('event', onEv); bus.on('incident', onInc); bus.on('notification', onNtf); bus.on('ticket', onTk); handlers = [['event', onEv], ['incident', onInc], ['notification', onNtf], ['ticket', onTk]];
  const prune = () => { try { const n = db.prune(retentionDays); if (n) audit.log('SYSTEM', 'EVENTS_PRUNED', { deleted: n, retentionDays }); } catch (e) { console.error('[persist] prune', e.message); } };
  prune(); pruneTimer = setInterval(prune, 6 * 3600e3); pruneTimer.unref();
  return { db, audit: log, ...r };
}
module.exports = { start, stop };
