'use strict';
process.env.PHOENIX_DB = process.env.PHOENIX_DB || ':memory:'; process.env.PHOENIX_QUIET = '1';
const cmd = require('../server/agents/commander');
const audit = require('../server/core/audit');
const events = require('../server/core/events');
const sim = require('../server/sim/enterprise');
const scen = require('../server/scenarios');
const autonomy = require('../server/core/autonomy');
let attached = false;
function fresh(mode = 'balanced') { if (!attached) { cmd.attach(); attached = true; } autonomy.reset(); autonomy.setMode(mode, 'test', { silent: true }); cmd.reset(); audit.reset(); events.reset(); sim.reset(); Object.assign(cmd.settings, { paceMs: 0, correlateMs: 250, autopilot: true }); }
async function until(fn, ms = 8000) { const t = Date.now(); while (Date.now() - t < ms) { const v = fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)); } throw new Error('timeout waiting for condition'); }
async function run(id, opts = {}) { fresh(opts.mode); if (opts.autopilot === false) cmd.settings.autopilot = false; await scen.launch(id, { speed: 0 }); const inc = await until(() => [...cmd.incidents.values()][0]); return inc; }
const settled = (inc) => until(() => ['RESOLVED', 'CLOSED'].includes(inc.state) || inc.status === 'Needs Attention');
module.exports = { autonomy, cmd, audit, events, sim, run, until, settled, fresh };
