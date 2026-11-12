'use strict';
// GAME DAY: scheduled rehearsals of every suggested scenario. Keeps a readiness score history and raises an alert when it drops.
const crypto = require('crypto'); const db = require('../core/db'); const audit = require('../core/audit'); const rehearse = require('./rehearse'); const log = require('../core/log');
let timer = null, listeners = [];
const onDrop = (fn) => listeners.push(fn);
async function run(by = 'system') {
  const prev = latest(), sug = rehearse.suggest().slice(0, 12), items = [];
  for (const s of sug) { try { const r = await rehearse.run({ scenario: s.scenario, target: s.target, by: 'gameday' }); items.push({ label: s.label, scenario: s.scenario, target: s.target, score: r.score, verdict: r.verdict, missing: r.missing.length, blockers: r.blockers }); } catch (e) { items.push({ label: s.label, scenario: s.scenario, target: s.target, error: String(e.message).slice(0, 100) }); } }
  const ok = items.filter((i) => i.score != null), score = ok.length ? Math.round(ok.reduce((s, i) => s + i.score, 0) / ok.length) : null, worst = ok.slice().sort((a, b) => a.score - b.score)[0] || null;
  const rep = { id: 'gd-' + crypto.randomBytes(4).toString('hex'), at: new Date().toISOString(), score, worst: worst && { label: worst.label, score: worst.score, verdict: worst.verdict }, notReady: ok.filter((i) => i.verdict === 'NOT_READY').length, items };
  rep.delta = prev && prev.score != null && score != null ? score - prev.score : null;
  const newlyBad = prev ? ok.filter((i) => i.verdict === 'NOT_READY' && (prev.items.find((p) => p.target === i.target && p.scenario === i.scenario) || {}).verdict !== 'NOT_READY') : [];
  rep.alert = (rep.delta != null && rep.delta <= -10) || newlyBad.length > 0;
  db.get().prepare('insert into rz_runs(id,kind,ref,status,result,by,at) values(?,?,?,?,?,?,?)').run(rep.id, 'gameday', null, String(score), JSON.stringify(rep), by, rep.at);
  audit.log(by, 'RZ_GAMEDAY', { id: rep.id, score, delta: rep.delta, alert: rep.alert });
  if (rep.alert) for (const f of listeners) try { f(rep, newlyBad); } catch (e) { log.warn?.('gameday listener', { error: e.message }); }
  return rep;
}
const latest = () => { const r = db.get().prepare("select result from rz_runs where kind='gameday' order by at desc limit 1").get(); return r ? JSON.parse(r.result) : null; };
const history = (n = 20) => db.get().prepare("select result from rz_runs where kind='gameday' order by at desc limit ?").all(n).map((r) => { const x = JSON.parse(r.result); return { id: x.id, at: x.at, score: x.score, delta: x.delta, notReady: x.notReady, alert: x.alert }; });
function start(hours = +process.env.PHOENIX_GAMEDAY_HOURS || 0) {
  stop(); if (!hours) return false;
  timer = setInterval(() => { try { const l = latest(); if ((!l || Date.now() - Date.parse(l.at) >= hours * 36e5) && rehearse.suggest().length) run('gameday').catch((e) => log.warn?.('gameday failed', { error: e.message })); } catch { /* ignore */ } }, 300000); timer.unref?.(); return true;
}
function stop() { if (timer) clearInterval(timer); timer = null; }
module.exports = { run, latest, history, start, stop, onDrop };
