'use strict';
// Online-safe backup of the PHOENIX database:  node scripts/backup.js [destination-file]
// Uses SQLite "VACUUM INTO" (consistent snapshot while the server is running). Also prunes backups older than PHOENIX_BACKUP_KEEP_DAYS (default 14).
try { process.loadEnvFile(require('path').join(__dirname, '..', '.env')); } catch { /* optional */ }
const fs = require('fs'); const path = require('path'); const cfg = require('../server/core/config'); const { DatabaseSync } = require('node:sqlite');
if (!fs.existsSync(cfg.dbPath)) { console.error('No database at ' + cfg.dbPath); process.exit(1); }
const dest = process.argv[2] || path.join(cfg.backupDir, `phoenix-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);
fs.mkdirSync(path.dirname(dest), { recursive: true });
const db = new DatabaseSync(cfg.dbPath); db.exec('PRAGMA busy_timeout=5000'); db.prepare('VACUUM INTO ?').run(dest); db.close();
try { fs.chmodSync(dest, 0o600); } catch { /* windows */ }
console.log('Backup written: ' + dest + ' (' + fs.statSync(dest).size + ' bytes)');
const keep = (+process.env.PHOENIX_BACKUP_KEEP_DAYS || 14) * 864e5;
if (!process.argv[2]) for (const f of fs.readdirSync(cfg.backupDir)) { const p = path.join(cfg.backupDir, f); if (/^phoenix-.*\.db$/.test(f) && Date.now() - fs.statSync(p).mtimeMs > keep) { fs.rmSync(p); console.log('Pruned old backup ' + f); } }
