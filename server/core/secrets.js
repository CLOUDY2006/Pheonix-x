'use strict';
// AES-256-GCM encryption for stored API tokens. Key: PHOENIX_SECRET_KEY (any long string) or an auto-generated
// file next to the database (mode 0600). With an in-memory DB the key lives only in RAM.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cfg = require('./config');
let key = null;
function getKey() {
  if (key) return key;
  const env = process.env.PHOENIX_SECRET_KEY;
  if (env) { if (env.length < 16) throw new Error('PHOENIX_SECRET_KEY must be at least 16 characters'); key = crypto.scryptSync(env, 'phoenix-x-secrets-v1', 32); return key; }
  if (cfg.dbPath === ':memory:') { key = crypto.randomBytes(32); return key; }
  const f = path.join(path.dirname(path.resolve(cfg.dbPath)), '.secret');
  try { key = Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex'); if (key.length !== 32) throw new Error('bad'); } catch { key = crypto.randomBytes(32); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, key.toString('hex'), { mode: 0o600 }); }
  return key;
}
function encrypt(plain) { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', getKey(), iv); const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]); return 'v1.' + [iv, c.getAuthTag(), ct].map((b) => b.toString('base64')).join('.'); }
function decrypt(blob) { const [v, iv, tag, ct] = String(blob).split('.'); if (v !== 'v1') throw new Error('unknown secret format'); const d = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(iv, 'base64')); d.setAuthTag(Buffer.from(tag, 'base64')); return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8'); }
module.exports = { encrypt, decrypt, _reset() { key = null; } };
