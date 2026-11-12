'use strict';
// Structured JSON logs to stdout (one line per record) — ready for any log shipper.
const cfg = require('./config');
const LV = { debug: 10, info: 20, warn: 30, error: 40 };
const out = (level, msg, extra) => { if (LV[level] < (LV[cfg.logLevel] || 20) || process.env.PHOENIX_QUIET) return; process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra }) + '\n'); };
module.exports = { debug: (m, e) => out('debug', m, e), info: (m, e) => out('info', m, e), warn: (m, e) => out('warn', m, e), error: (m, e) => out('error', m, e) };
