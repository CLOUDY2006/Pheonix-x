'use strict';
// Central configuration + startup validation. Read once at require time.
const path = require('path');
const E = process.env;
const on = (v, d = false) => (v === undefined || v === '' ? d : /^(1|on|true|yes)$/i.test(String(v)));
const mode = (E.PHOENIX_MODE || 'demo').toLowerCase() === 'production' ? 'production' : 'demo';
const isProd = mode === 'production';
const root = path.join(__dirname, '..', '..');
const cfg = {
  mode, isProd,
  port: +E.PORT || 3000, host: E.HOST || '127.0.0.1',
  dbPath: E.PHOENIX_DB || path.join(root, 'data', 'phoenix.db'),
  backupDir: E.PHOENIX_BACKUP_DIR || path.join(root, 'data', 'backups'),
  retentionDays: +E.PHOENIX_RETENTION_DAYS || 30,
  tls: { cert: E.PHOENIX_TLS_CERT, key: E.PHOENIX_TLS_KEY },
  trustProxy: on(E.PHOENIX_TRUST_PROXY), cookieSecure: on(E.PHOENIX_COOKIE_SECURE, isProd),
  sessionHours: +E.PHOENIX_SESSION_HOURS || 8, idleMinutes: +E.PHOENIX_IDLE_MINUTES || 60,
  setupToken: E.PHOENIX_SETUP_TOKEN || null, requireAdminTotp: on(E.PHOENIX_REQUIRE_ADMIN_TOTP),
  seedDemoUsers: on(E.PHOENIX_SEED_DEMO_USERS, !isProd),
  generator: on(E.PHOENIX_GENERATOR, !isProd), allowScenarios: on(E.PHOENIX_ALLOW_SCENARIOS, !isProd),
  autonomy: ['watch','balanced','full'].includes(E.PHOENIX_AUTONOMY) ? E.PHOENIX_AUTONOMY : null, // watch | balanced | full (demo default balanced, production default watch)
  autoContain: on(E.PHOENIX_AUTO_CONTAIN, !isProd || ['balanced', 'full'].includes(E.PHOENIX_AUTONOMY)), // legacy kill-switch; follows the autonomy mode
  approvalTimeoutMin: +(E.PHOENIX_APPROVAL_TIMEOUT_MIN ?? (isProd ? 30 : 0)),
  paceMs: +(E.PHOENIX_PACE_MS ?? (isProd ? 0 : 1000)), correlateMs: +(E.PHOENIX_CORRELATE_MS ?? (isProd ? 5000 : 1500)),
  metricsToken: E.PHOENIX_METRICS_TOKEN || null, logLevel: E.PHOENIX_LOG_LEVEL || 'info',
  connectorDryRun: on(E.PHOENIX_CONNECTOR_DRYRUN, true), // live connectors only act when this is explicitly turned OFF
  connectors: { identity: E.PHOENIX_CONNECTOR_IDENTITY || (isProd ? 'none' : 'sim'), network: E.PHOENIX_CONNECTOR_NETWORK || (isProd ? 'none' : 'sim'), endpoint: E.PHOENIX_CONNECTOR_ENDPOINT || (isProd ? 'none' : 'sim'), data: E.PHOENIX_CONNECTOR_DATA || (isProd ? 'none' : 'sim'), cloud: E.PHOENIX_CONNECTOR_CLOUD || (isProd ? 'none' : 'sim') },
};
function validate() {
  const warn = [], fatal = [];
  if (isProd) {
    if (cfg.host !== '127.0.0.1' && cfg.host !== 'localhost' && !cfg.tls.cert && !cfg.trustProxy) warn.push('HOST is not loopback but neither TLS (PHOENIX_TLS_CERT/KEY) nor PHOENIX_TRUST_PROXY=on is set: terminate TLS in front of this server.');
    if (cfg.seedDemoUsers) fatal.push('PHOENIX_SEED_DEMO_USERS=on is not allowed in production mode (demo accounts have a published password).');
    if (cfg.generator) warn.push('Synthetic event generator is enabled in production: it will pollute real data.');
    if (cfg.connectorDryRun) warn.push('Live connectors are in DRY-RUN (PHOENIX_CONNECTOR_DRYRUN=on): no real containment will happen until you set it to off.');
    if (Object.values(cfg.connectors).some((v) => v === 'sim')) fatal.push('Simulated connectors ("sim") cannot be used in production mode.');
  }
  if ((cfg.tls.cert && !cfg.tls.key) || (!cfg.tls.cert && cfg.tls.key)) fatal.push('Both PHOENIX_TLS_CERT and PHOENIX_TLS_KEY are required for TLS.');
  return { warn, fatal };
}
module.exports = Object.assign(cfg, { validate, on });
