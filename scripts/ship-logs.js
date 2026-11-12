#!/usr/bin/env node
'use strict';
// Ship a log file to PHOENIX X. No dependencies (Node 18+).
//   node scripts/ship-logs.js --url https://phoenix.example.com --key phx_... --format nginx --file /var/log/nginx/access.log
// Formats: nginx (access logs) | syslog (sshd/auth.log) | cef | windows | any format your key is bound to that takes {lines:[...]}.
// Options: --from-start (backfill the whole file; default starts at the end), --once (send what is there and exit), --batch 200, --interval 1000
const fs = require('fs'); const os = require('os'); const path = require('path'); const crypto = require('crypto');
const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i < 0 ? d : (process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[i + 1] : true); };
const url = String(arg('url', process.env.PHOENIX_URL || '')).replace(/\/$/, ''), key = arg('key', process.env.PHOENIX_KEY), format = arg('format', 'nginx'), file = arg('file');
const batchN = +arg('batch', 200), interval = +arg('interval', 1000), once = !!arg('once', false), fromStart = !!arg('from-start', false);
if (!url || !key || !file) { console.error('usage: ship-logs.js --url <https://phoenix> --key <phx_...> --format <nginx|syslog|cef|windows> --file <path> [--from-start] [--once]'); process.exit(2); }
const stateDir = process.env.PHOENIX_SHIP_STATE || path.join(os.homedir(), '.phoenix-ship'); fs.mkdirSync(stateDir, { recursive: true });
const stateFile = path.join(stateDir, crypto.createHash('sha1').update(path.resolve(file) + format).digest('hex') + '.json');
let st = { offset: null, ino: null }; try { st = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { /* first run */ }
const save = () => fs.writeFileSync(stateFile, JSON.stringify(st));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function post(lines) {
  const r = await fetch(`${url}/api/ingest/${format}`, { method: 'POST', headers: { 'x-api-key': key, 'content-type': 'application/json' }, body: JSON.stringify({ lines }), signal: AbortSignal.timeout(15000) });
  if (r.status === 401 || r.status === 403) { console.error('PHOENIX rejected the key (' + r.status + ') - check --key and the format it is bound to'); process.exit(1); }
  if (!r.ok && r.status !== 422) throw new Error('HTTP ' + r.status); return r.json().catch(() => ({}));
}
let tail = '', backoff = 1000;
async function cycle() {
  let s; try { s = fs.statSync(file); } catch { return; }
  if (st.offset === null) st.offset = fromStart ? 0 : s.size; // do not flood the SOC with old history unless asked
  if (st.ino !== null && st.ino !== s.ino || s.size < st.offset) { st.offset = 0; tail = ''; } // rotated or truncated
  st.ino = s.ino; if (s.size === st.offset) return;
  const fd = fs.openSync(file, 'r'); let sent = 0;
  try {
    while (st.offset < s.size) {
      const len = Math.min(1 << 20, s.size - st.offset), buf = Buffer.alloc(len); fs.readSync(fd, buf, 0, len, st.offset);
      const text = tail + buf.toString('utf8'); const parts = text.split('\n'); const rest = parts.pop(); const lines = parts.filter((l) => l.trim());
      for (let i = 0; i < lines.length; i += batchN) { const r = await post(lines.slice(i, i + batchN)); sent += r.accepted || 0; }
      tail = rest; st.offset += len; save(); // advance only after the server accepted the batch
    }
  } finally { fs.closeSync(fd); }
  backoff = 1000; if (sent) console.log(new Date().toISOString(), 'shipped', sent, 'events from', file);
}
(async () => { for (;;) { try { await cycle(); } catch (e) { console.error('ship error:', e.message, '- retrying in', backoff, 'ms'); await sleep(backoff); backoff = Math.min(60000, backoff * 2); } if (once) break; await sleep(interval); } })();
