'use strict';
// Controlled, in-memory simulated enterprise. NOTHING here touches real systems.
// Every containment/recovery action in the demo mutates only this object.
const { sha256 } = require('../core/util');
const cfg = require('../core/config');

function build() {
  if (cfg.isProd) return { users: {}, hosts: {}, backups: {}, resources: {}, cloud: { roles: {}, buckets: {}, accessKeys: {}, trailLogging: true }, firewall: { blockedIPs: new Set() }, tickets: [], outbox: [] };
  const users = {
    'alice.chen':   { dept: 'Finance',     role: 'analyst',  homeGeo: 'US-NY', devices: ['ws-alice-01'], env: 'sandbox', status: 'active', mfa: true },
    'bob.martin':   { dept: 'Engineering', role: 'engineer', homeGeo: 'GB-LON', devices: ['ws-bob-01'], env: 'sandbox', status: 'active', mfa: true },
    'carol.diaz':   { dept: 'HR',          role: 'hr-lead',  homeGeo: 'US-TX', devices: ['ws-carol-01'], env: 'sandbox', status: 'active', mfa: true },
    'dave.okafor':  { dept: 'IT',          role: 'sysadmin', homeGeo: 'US-NY', devices: ['ws-dave-01'], env: 'sandbox', status: 'active', mfa: true },
    'erin.novak':   { dept: 'Executive',   role: 'cfo',      homeGeo: 'US-NY', devices: ['ws-erin-01'], env: 'sandbox', status: 'active', mfa: true },
    'frank.li':     { dept: 'Engineering', role: 'engineer', homeGeo: 'SG-SIN', devices: ['ws-frank-01'], env: 'sandbox', status: 'active', mfa: false },
  };
  for (const u of Object.values(users)) { u.sessions = []; u.tokens = []; }
  const hosts = {
    'ws-alice-01':  { kind: 'workstation', owner: 'alice.chen', env: 'sandbox', criticality: 'low' },
    'ws-bob-01':    { kind: 'workstation', owner: 'bob.martin', env: 'sandbox', criticality: 'low' },
    'ws-carol-01':  { kind: 'workstation', owner: 'carol.diaz', env: 'sandbox', criticality: 'low' },
    'ws-dave-01':   { kind: 'workstation', owner: 'dave.okafor', env: 'sandbox', criticality: 'low' },
    'ws-erin-01':   { kind: 'workstation', owner: 'erin.novak', env: 'sandbox', criticality: 'medium' },
    'ws-frank-01':  { kind: 'workstation', owner: 'frank.li', env: 'sandbox', criticality: 'low' },
    'srv-files-01': { kind: 'server', role: 'file-server', env: 'sandbox', criticality: 'high' },
    'srv-app-01':   { kind: 'server', role: 'app-server', env: 'sandbox', criticality: 'medium' },
    'prod-db-01':   { kind: 'server', role: 'database', env: 'production', criticality: 'critical' },
  };
  for (const h of Object.values(hosts)) { h.isolated = false; h.status = 'online'; h.contentHash = sha256('clean-' + Math.random()); h.compromised = false; }
  const day = 86400e3, now = Date.now();
  const backups = {
    'srv-files-01': [{ id: 'bk-f-0412', ts: new Date(now - 14 * 3600e3).toISOString(), verified: true, immutable: true, sizeGB: 812 }, { id: 'bk-f-0411', ts: new Date(now - 38 * 3600e3).toISOString(), verified: true, immutable: true, sizeGB: 809 }],
    'ws-alice-01':  [{ id: 'bk-a-0330', ts: new Date(now - 9 * day).toISOString(), verified: false, immutable: false, sizeGB: 96 }],
    'srv-app-01':   [{ id: 'bk-s-0412', ts: new Date(now - 14 * 3600e3).toISOString(), verified: true, immutable: true, sizeGB: 210 }],
    'prod-db-01':   [{ id: 'bk-d-0412', ts: new Date(now - 3 * 3600e3).toISOString(), verified: true, immutable: true, sizeGB: 2400 }],
    // ws-carol-01 intentionally has NO backup -> recovery readiness gap in demos
  };
  const resources = {
    '/finance/Q3-forecast.xlsx': { owner: 'erin.novak', sensitivity: 'confidential', env: 'sandbox', restricted: false },
    '/finance/payroll-2026.csv': { owner: 'alice.chen', sensitivity: 'restricted', env: 'sandbox', restricted: false },
    '/hr/employee-records': { owner: 'carol.diaz', sensitivity: 'restricted', env: 'sandbox', restricted: false },
    '/eng/source/core-platform': { owner: 'bob.martin', sensitivity: 'confidential', env: 'sandbox', restricted: false },
    '/prod/customers.db': { owner: 'dave.okafor', sensitivity: 'restricted', env: 'production', restricted: false },
  };
  const cloud = {
    roles: { 'ci-deploy-role': { policies: ['ReadOnlyAccess'], env: 'sandbox' }, 'dev-sandbox-role': { policies: ['PowerUserAccess'], env: 'sandbox' } },
    buckets: { 'phx-demo-finance-exports': { public: false, env: 'sandbox' }, 'phx-demo-backups': { public: false, env: 'sandbox' } },
    accessKeys: {},
    trailLogging: true,
  };
  return { users, hosts, backups, resources, cloud, firewall: { blockedIPs: new Set() }, tickets: [], outbox: [] };
}

let env = build();
module.exports = {
  get env() { return env; },
  reset() { env = build(); return env; },
  snapshot() {
    return {
      users: Object.fromEntries(Object.entries(env.users).map(([k, u]) => [k, { dept: u.dept, role: u.role, status: u.status, sessions: u.sessions.length, tokens: u.tokens.length, mfa: u.mfa }])),
      hosts: env.hosts, backups: env.backups, resources: env.resources, cloud: env.cloud,
      blockedIPs: [...env.firewall.blockedIPs],
    };
  },
};
