'use strict';
// Alert suppressions / allow-lists: the standard way to tame false positives. Every entry has an owner, a reason and
// (optionally) an expiry, and all changes are audited. A suppressed alert is counted and sampled in the audit log.
const db = require('./db');
const audit = require('./audit');
const { uid } = require('./util');

let list = [], suppressed = 0, lastLog = 0;
const load = () => { list = db.get().prepare('select * from suppressions').all(); };
const active = () => list.filter((s) => !s.expires_at || new Date(s.expires_at) > new Date());
function match(rule, affected) {
  for (const s of active()) {
    if (s.rule !== '*' && s.rule !== rule) continue;
    if (!s.user && !s.ip && !s.host) { if (s.rule === '*') continue; } // a bare rule-wide suppression is allowed only for a named rule
    if (s.user && !(affected.users || []).includes(s.user)) continue;
    if (s.ip && !(affected.ips || []).includes(s.ip)) continue;
    if (s.host && !(affected.hosts || []).includes(s.host)) continue;
    suppressed++; if (Date.now() - lastLog > 60e3) { lastLog = Date.now(); audit.log('SENTINEL', 'ALERT_SUPPRESSED', { rule, suppression: s.id, reason: s.reason, totalSuppressed: suppressed }); }
    return true;
  }
  return false;
}
function add({ rule, user, ip, host, reason, expiresInHours }, by) {
  if (!rule || typeof rule !== 'string' || rule.length > 40) throw new Error('rule required (rule id or "*")');
  if (!reason || String(reason).length < 5) throw new Error('a reason of at least 5 characters is required');
  if (rule === '*' && !user && !ip && !host) throw new Error('"*" needs a user, ip or host scope');
  const s = { id: uid('sup'), rule, user: user || null, ip: ip || null, host: host || null, reason: String(reason).slice(0, 300), created_by: by, created_at: new Date().toISOString(), expires_at: expiresInHours ? new Date(Date.now() + expiresInHours * 3600e3).toISOString() : null };
  db.get().prepare('insert into suppressions(id,rule,user,ip,host,reason,created_by,created_at,expires_at) values(?,?,?,?,?,?,?,?,?)').run(s.id, s.rule, s.user, s.ip, s.host, s.reason, s.created_by, s.created_at, s.expires_at);
  list.push(s); audit.log(by, 'SUPPRESSION_ADDED', s); return s;
}
function remove(id, by) { db.get().prepare('delete from suppressions where id=?').run(id); list = list.filter((s) => s.id !== id); audit.log(by, 'SUPPRESSION_REMOVED', { id }); }
module.exports = { load, match, add, remove, list: () => active(), count: () => suppressed };
