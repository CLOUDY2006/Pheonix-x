'use strict';
// Break-glass administration from the server console (works while the server is stopped or running).
//   node scripts/admin.js create-admin <username> <password>
//   node scripts/admin.js reset-password <username> <new-password>
//   node scripts/admin.js disable-2fa <username>
//   node scripts/admin.js list
try { process.loadEnvFile(require('path').join(__dirname, '..', '.env')); } catch { /* optional */ }
const cfg = require('../server/core/config'); const dbm = require('../server/core/db'); const auth = require('../server/core/auth');
dbm.open(cfg.dbPath);
const [cmd, a, b] = process.argv.slice(2);
try {
  if (cmd === 'create-admin') { auth.createUser({ username: a, password: b, role: 'admin' }, 'CLI'); console.log('Admin created: ' + a); }
  else if (cmd === 'reset-password') { auth.updateUser(a, { password: b }, 'CLI'); console.log('Password reset (all sessions revoked): ' + a); }
  else if (cmd === 'disable-2fa') { auth.totpDisable(a, 'CLI'); auth.revokeAll(a); console.log('2FA disabled for ' + a); }
  else if (cmd === 'list') console.table(auth.listUsers());
  else { console.log('usage: node scripts/admin.js create-admin|reset-password|disable-2fa|list ...'); process.exit(2); }
} catch (e) { console.error('Error: ' + e.message); process.exit(1); }
dbm.close();
