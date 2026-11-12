'use strict';
// Synthetic attack scenarios. Every event is origin="scenario" (clearly SIMULATED) and only mutates the in-memory sim.
const events = require('../core/events');
const sim = require('../sim/enterprise');
const bus = require('../core/bus');
const audit = require('../core/audit');
const { hashes } = require('../agents/oracle');
const { sleep } = require('../core/util');

const speed = { v: 1 };
const ATT = '198.19.66.14', C2 = '198.19.66.77', TOKEN_IP = '198.19.88.23', EXFIL = '198.19.120.40', PHISH = 'secure-payroll-login.example';

function ctx(id) {
  const step = (name) => bus.emit('scenario', { id, step: name, ts: new Date().toISOString() });
  const ev = (e) => events.add({ origin: 'scenario', scenarioId: id, ...e }, 'scenario');
  const wait = (ms) => sleep(ms * speed.v);
  return { step, ev, wait };
}

const SCENARIOS = [
  { id: 'credential-compromise', name: 'Credential Compromise', icon: '🔑', blurb: 'Brute-force → successful login from Moscow → bulk payroll download → token replay.', run: async () => {
    const { step, ev, wait } = ctx('credential-compromise'); const u = 'alice.chen';
    step('Normal activity: Alice uses her API token from New York');
    ev({ source: 'api', type: 'api_call', user: u, ip: '198.51.100.31', geo: 'US-NY', resource: '/v1/reports', outcome: 'success', orgHour: 10, details: { status: 200, tokenId: 'tok-' + u } }); await wait(400);
    step('Attacker begins guessing passwords from ' + ATT);
    for (let i = 0; i < 7; i++) { ev({ source: 'authentication', type: 'login_failed', user: u, ip: ATT, geo: 'RU-MOW', outcome: 'failure', orgHour: 3, details: { reason: 'bad_password', mfa: false } }); await wait(350); }
    step('Login succeeds from an unknown device in Moscow, no MFA');
    sim.env.users[u].sessions.push('sess-9f2a41 (RU-MOW)', 'sess-31bc07 (US-NY)'); sim.env.users[u].tokens.push('tok-' + u);
    ev({ source: 'authentication', type: 'login_success', user: u, ip: ATT, geo: 'RU-MOW', device: 'unknown-dev-77', outcome: 'success', orgHour: 3, details: { mfa: false, knownDevice: false, suspicious: true } }); await wait(700);
    step('Attacker pivots to the file server');
    ev({ source: 'system', type: 'lateral_access', user: u, ip: ATT, host: 'srv-files-01', geo: 'RU-MOW', orgHour: 3, details: { protocol: 'SMB', fromHost: 'vpn-gateway' } }); await wait(500);
    step('Token replayed from a different country');
    ev({ source: 'api', type: 'api_call', user: u, ip: ATT, geo: 'RU-MOW', resource: '/v1/reports/export', outcome: 'success', orgHour: 3, details: { status: 200, tokenId: 'tok-' + u } }); await wait(500);
    step('Bulk download of payroll data (140 files, 600 MB)');
    ev({ source: 'file', type: 'file_download', user: u, ip: ATT, host: 'srv-files-01', resource: '/finance/payroll-2026.csv', count: 140, bytes: 600e6, orgHour: 3, geo: 'RU-MOW', outcome: 'success' });
  } },
  { id: 'ransomware', name: 'Ransomware Simulation', icon: '🔒', blurb: 'Macro dropper → C2 beaconing → shadow copies deleted → mass rename (synthetic; nothing is encrypted).', run: async () => {
    const { step, ev, wait } = ctx('ransomware'); const u = 'carol.diaz', h = 'ws-carol-01';
    step('Office macro launches a script on ' + h);
    ev({ source: 'system', type: 'macro_exec', user: u, host: h, hash: hashes.locker, orgHour: 11, details: { parent: 'winword.exe', child: 'wscript.exe' } }); await wait(700);
    step('Implant beacons to command-and-control');
    for (let i = 0; i < 6; i++) { ev({ source: 'network', type: 'beacon', user: u, host: h, ip: C2, domain: 'cdn-update-check.example', bytes: 900, orgHour: 11 }); await wait(250); }
    step('Shadow copies deleted to block recovery');
    ev({ source: 'system', type: 'shadow_copy_deleted', user: u, host: h, orgHour: 11, details: { process: 'vssadmin.exe' } }); await wait(600);
    step('Mass file renames to .phxlock on workstation');
    for (let i = 0; i < 4; i++) { ev({ source: 'file', type: 'file_rename', user: u, host: h, count: 30, resource: '/users/carol/Documents/*.phxlock', orgHour: 11, details: { newExt: '.phxlock' } }); await wait(250); }
    step('Spreads over SMB to the file server');
    ev({ source: 'system', type: 'lateral_access', user: u, host: 'srv-files-01', ip: '10.0.4.23', orgHour: 11, details: { protocol: 'SMB', fromHost: h } }); await wait(400);
    for (let i = 0; i < 5; i++) { ev({ source: 'file', type: 'file_rename', user: u, host: 'srv-files-01', count: 45, resource: '/hr/employee-records/*.phxlock', orgHour: 11, details: { newExt: '.phxlock' } }); await wait(200); }
  } },
  { id: 'insider-threat', name: 'Insider Threat', icon: '🕵️', blurb: 'Off-hours bulk source download, self-granted admin, 450 MB upload to personal storage.', run: async () => {
    const { step, ev, wait } = ctx('insider-threat'); const u = 'frank.li', h = 'ws-frank-01';
    step('Engineer logs in at 02:10 local, no MFA enrolled');
    ev({ source: 'authentication', type: 'login_success', user: u, host: h, device: h, ip: '198.18.0.44', geo: 'SG-SIN', orgHour: 2, details: { mfa: false, knownDevice: true } }); await wait(600);
    step('Self-assigns repo-admin without a change ticket');
    ev({ source: 'authentication', type: 'privilege_change', user: u, host: 'srv-app-01', orgHour: 2, details: { actor: u, newRole: 'repo-admin', ticket: null } }); await wait(600);
    step('Bulk download of core-platform source (3 × 60 files)');
    for (let i = 0; i < 3; i++) { ev({ source: 'file', type: 'file_download', user: u, host: h, resource: '/eng/source/core-platform', count: 60, bytes: 120e6, orgHour: 2, geo: 'SG-SIN', outcome: 'success' }); await wait(400); }
    step('450 MB upload to an unknown external address (not in threat intel)');
    ev({ source: 'network', type: 'outbound_conn', user: u, host: h, ip: EXFIL, domain: 'personal-share.example', bytes: 450e6, orgHour: 2, outcome: 'success' });
  } },
  { id: 'phishing', name: 'Phishing Attack', icon: '🎣', blurb: 'User reports an email; AI statically analyses it (URLs never opened), finds clickers, opens a ticket.', run: async () => {
    const { step, ev, wait } = ctx('phishing');
    const body = `Dear colleague,\nURGENT: your payroll password expires within 24 hours. Verify your account immediately to avoid suspension:\nhttps://${PHISH}/verify?u=bob.martin\nThanks,\nPayroll Helpdesk`;
    step('Two employees click the link before anyone reports');
    for (const [u, h] of [['alice.chen', 'ws-alice-01'], ['erin.novak', 'ws-erin-01']]) { ev({ source: 'application', type: 'email_link_click', user: u, host: h, domain: PHISH, orgHour: 9, details: { domainAgeDays: 4, url: `https://${PHISH}/verify` } }); await wait(300); }
    step('Bob reports the suspicious email');
    ev({ source: 'application', type: 'email_reported', user: 'bob.martin', orgHour: 10, details: { subject: 'URGENT: payroll password expires within 24 hours', from: 'helpdesk@payroll-support.example', replyTo: 'collect@payroll-support.example', body, urls: [`https://${PHISH}/verify?u=bob.martin`], recipients: ['bob.martin', 'alice.chen', 'erin.novak', 'dave.okafor'] } });
  } },
  { id: 'cloud-compromise', name: 'Cloud Account Compromise', icon: '☁️', blurb: 'API enumeration → AdministratorAccess granted → new key → bucket made public → attempt to stop CloudTrail.', run: async () => {
    const { step, ev, wait } = ctx('cloud-compromise'); const u = 'svc-deploy';
    step('Stolen CI key is used to enumerate the account (16 × 403)');
    for (let i = 0; i < 16; i++) { ev({ source: 'api', type: 'api_call', user: u, ip: TOKEN_IP, geo: 'RO-BUC', resource: '/iam/ListRoles', outcome: 'failure', orgHour: 4, details: { status: 403, tokenId: 'tok-' + u } }); await wait(120); }
    step('AdministratorAccess attached to dev-sandbox-role');
    sim.env.cloud.roles['dev-sandbox-role'].policies.push('AdministratorAccess');
    ev({ source: 'cloud', type: 'iam_attach_policy', user: u, ip: TOKEN_IP, resource: 'dev-sandbox-role', orgHour: 4, details: { policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess', eventName: 'AttachRolePolicy' } }); await wait(500);
    step('Persistent access key created');
    sim.env.cloud.accessKeys['AKIA-SIM-0001'] = { role: 'dev-sandbox-role', createdBy: u };
    ev({ source: 'cloud', type: 'create_access_key', user: u, ip: TOKEN_IP, resource: 'dev-sandbox-role', orgHour: 4, details: { eventName: 'CreateAccessKey' } }); await wait(500);
    step('Finance export bucket made public');
    sim.env.cloud.buckets['phx-demo-finance-exports'].public = true;
    ev({ source: 'cloud', type: 'put_bucket_acl', user: u, ip: TOKEN_IP, resource: 'phx-demo-finance-exports', orgHour: 4, details: { acl: 'public', eventName: 'PutBucketAcl' } }); await wait(500);
    step('Attacker tries to stop audit logging');
    ev({ source: 'cloud', type: 'stop_logging', user: u, ip: TOKEN_IP, resource: 'org-trail', orgHour: 4, details: { eventName: 'StopLogging' } });
  } },
  { id: 'benign-travel', name: 'Benign: Traveling Employee', icon: '✈️', blurb: 'Known device + MFA from a new city. Should be triaged to MONITOR — no containment (tests false-positive restraint).', run: async () => {
    const { step, ev } = ctx('benign-travel');
    step('Bob logs in from New York on his own laptop with MFA');
    ev({ source: 'authentication', type: 'login_success', user: 'bob.martin', host: 'ws-bob-01', device: 'ws-bob-01', ip: '198.51.100.77', geo: 'US-NY', orgHour: 14, details: { mfa: true, knownDevice: true } });
  } },
];

const byId = (id) => SCENARIOS.find((s) => s.id === (id === 'signature' ? 'credential-compromise' : id));
async function launch(id, opts = {}) {
  const s = byId(id); if (!s) throw new Error('unknown scenario'); speed.v = opts.speed ?? 1;
  if (opts.reset) sim.reset();
  audit.log('SCENARIO', 'SCENARIO_LAUNCHED', { id: s.id, note: 'synthetic events only; no real systems touched' }, null);
  bus.emit('scenario', { id: s.id, step: 'START', ts: new Date().toISOString() });
  await s.run(); bus.emit('scenario', { id: s.id, step: 'DONE', ts: new Date().toISOString() });
}
module.exports = { list: () => SCENARIOS.map(({ id, name, icon, blurb }) => ({ id, name, icon, blurb })), launch, speed };
