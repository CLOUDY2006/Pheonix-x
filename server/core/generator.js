'use strict';
// Background "normal day" traffic + occasional benign noise. Everything is origin=generated (SIMULATED).
const events = require('./events');
const sim = require('../sim/enterprise');
const { geos } = require('../sim/baselines');
const { pick } = require('./util');

let timer = null, rate = 700;
const ipFor = (geo) => (geos[geo]?.ip || '198.51.100.') + (10 + Math.floor(Math.random() * 200));

function tick() {
  const users = Object.entries(sim.env.users).filter(([, u]) => u.status === 'active');
  const [name, u] = pick(users);
  const device = u.devices[0], hour = 8 + Math.floor(Math.random() * 9);
  const base = { user: name, device, host: device, orgHour: hour, geo: u.homeGeo };
  const r = Math.random();
  if (r < 0.22) events.add({ ...base, source: 'authentication', type: 'login_success', ip: ipFor(u.homeGeo), outcome: 'success', details: { mfa: u.mfa, knownDevice: true } }, 'generated');
  else if (r < 0.50) events.add({ ...base, source: 'file', type: 'file_read', resource: pick(Object.keys(sim.env.resources).filter((k) => sim.env.resources[k].owner === name).concat(['/shared/handbook.pdf'])), bytes: Math.floor(5e4 + Math.random() * 3e6), count: 1, outcome: 'success', ip: ipFor(u.homeGeo) }, 'generated');
  else if (r < 0.75) events.add({ ...base, source: 'api', type: 'api_call', resource: pick(['/v1/reports', '/v1/orders', '/v1/profile', '/v1/search']), outcome: 'success', ip: ipFor(u.homeGeo), details: { status: 200, tokenId: 'tok-' + name } }, 'generated');
  else if (r < 0.88) events.add({ ...base, source: 'network', type: 'outbound_conn', ip: '93.184.216.' + (1 + Math.floor(Math.random() * 40)), domain: pick(['updates.vendor-ok.example', 'cdn.office-sim.example', 'mail.corp-sim.example']), bytes: Math.floor(1e3 + Math.random() * 4e5), outcome: 'success' }, 'generated');
  else if (r < 0.95) events.add({ ...base, source: 'system', type: 'process_start', resource: pick(['outlook.exe', 'chrome.exe', 'excel.exe', 'code.exe']), outcome: 'success' }, 'generated');
  else events.add({ ...base, source: 'authentication', type: 'login_failed', ip: ipFor(u.homeGeo), outcome: 'failure', details: { reason: 'bad_password', mfa: u.mfa } }, 'generated'); // benign typo, below any threshold
}
function start(ms = rate) { stop(); rate = ms; timer = setInterval(tick, rate); }
function stop() { if (timer) clearInterval(timer); timer = null; }
module.exports = { start, stop, tick, get running() { return !!timer; } };
