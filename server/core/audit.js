'use strict';
// Tamper-evident audit trail: each entry embeds the hash of the previous one.
const fs = require('fs');
const path = require('path');
const { sha256 } = require('./util');
const bus = require('./bus');

const chain = [];
let persist = process.env.PHOENIX_AUDIT_FILE || null;
let sink = null; // e.g. database writer
const setSink = (fn) => { sink = fn; };
function load(entries) { chain.length = 0; chain.push(...entries); return verify(); }

function log(actor, action, detail = {}, incidentId = null) {
  const prev = chain.length ? chain[chain.length - 1].hash : 'GENESIS';
  const entry = { seq: chain.length + 1, ts: new Date().toISOString(), actor, action, incidentId, detail, prev };
  entry.hash = sha256(prev + JSON.stringify([entry.seq, entry.ts, actor, action, incidentId, detail]));
  chain.push(entry);
  if (persist) { try { fs.mkdirSync(path.dirname(persist), { recursive: true }); fs.appendFileSync(persist, JSON.stringify(entry) + '\n'); } catch { persist = null; } }
  if (sink) { try { sink(entry); } catch { /* never let storage break auditing */ } }
  bus.emit('audit', entry);
  return entry;
}
function verify() {
  let prev = 'GENESIS';
  for (const e of chain) {
    const h = sha256(prev + JSON.stringify([e.seq, e.ts, e.actor, e.action, e.incidentId, e.detail]));
    if (e.prev !== prev || e.hash !== h) return { ok: false, brokenAt: e.seq, length: chain.length };
    prev = e.hash;
  }
  return { ok: true, length: chain.length, head: prev };
}
const forIncident = (id) => chain.filter((e) => e.incidentId === id);
const recent = (n = 200) => chain.slice(-n);
const reset = () => { chain.length = 0; };
module.exports = { load, log, setSink, verify, forIncident, recent, reset, _chain: chain };
