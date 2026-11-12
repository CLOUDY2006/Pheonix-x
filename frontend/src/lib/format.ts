import type { EventT, Step } from '../types';

export const fmtT = (ts: string) => new Date(ts).toLocaleTimeString([], { hour12: false });
export const fmtDT = (ts: string) => new Date(ts).toLocaleString([], { hour12: false });
export const nice = (t?: string) => String(t || '').replace(/_/g, ' ').replace(/^./, (m) => m.toUpperCase());
export const plain = (t?: string) => String(t || '').replace(/^[A-Z]{1,2}-[A-Z0-9-]+( risk \d+)?:\s*/, '').replace(/^./, (m) => m.toUpperCase());
export const riskWord = (r: number) => (r > 70 ? 'High' : r > 40 ? 'Moderate' : 'Low');

export const SEV: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
export const TIER: Record<string, string> = { automatic: 'Automatic', approval: 'Needs approval', restricted: 'Never automatic' };
export const SRC: Record<string, string> = { authentication: 'Sign-ins', application: 'Apps', system: 'Computers', network: 'Network', api: 'API', file: 'Files', cloud: 'Cloud' };
export const DISP: Record<string, string> = { respond: 'Contain and recover', monitor: 'Keep watching, no action needed' };
export const STATE_SHORT: Record<string, [string, 'ok' | 'warn' | 'info' | 'neutral' | 'ember']> = { DETECTED: ['Just spotted', 'ember'], TRIAGED: ['Checking it out', 'ember'], MONITORING: ['Watching', 'info'], INVESTIGATING: ['Working on it', 'ember'], ENRICHING: ['Working on it', 'ember'], PLANNING: ['Working on it', 'ember'], AWAITING_APPROVAL: ['Waiting for you', 'warn'], CONTAINING: ['Working on it', 'ember'], RECOVERING: ['Cleaning up', 'ember'], VERIFYING: ['Double-checking', 'ember'], RESOLVED: ['Handled', 'ok'], CLOSED: ['Handled', 'ok'] };
export const isActiveState = (s: string) => !['RESOLVED', 'CLOSED', 'MONITORING'].includes(s);
export const STATE_TXT: Record<string, string> = { DETECTED: 'Just detected', TRIAGED: 'Being assessed', MONITORING: 'Being watched (low risk)', INVESTIGATING: 'Investigating', ENRICHING: 'Checking threat lists', PLANNING: 'Planning a response', AWAITING_APPROVAL: 'Waiting for you', CONTAINING: 'Stopping the attack', RECOVERING: 'Recovering', VERIFYING: 'Checking the fix worked', RESOLVED: 'Handled', CLOSED: 'Handled' };
export const STEP_TXT: Record<string, string> = { receive: 'Receiving security events', group: 'Grouping related events', risk: 'Scoring how risky it is', investigate: 'Investigating what happened', enrich: 'Checking threat databases', assets: 'Finding affected systems', plan: 'Planning safe containment', authorize: 'Asking for approval', execute: 'Carrying out approved actions', recovery: 'Restoring systems', verify: 'Checking the fix worked', report: 'Writing the final report' };
export const AG_NAME: Record<string, string> = { SENTINEL: 'Sentinel', INVESTIGATOR: 'Investigator', ORACLE: 'Oracle', GUARDIAN: 'Guardian', RECOVERY: 'Recovery', COMMANDER: 'Commander' };
export const AG_COL: Record<string, string> = { SENTINEL: '#ff6b6b', INVESTIGATOR: '#7ea1ff', ORACLE: '#7a4fe0', GUARDIAN: '#2ee6a6', RECOVERY: '#d97706', COMMANDER: '#141d35' };

export const PHASES: { name: string; cap: string; keys: string[] }[] = [
  { name: 'Detect', cap: 'Spot something unusual', keys: ['receive', 'group', 'risk'] },
  { name: 'Investigate', cap: 'Work out what happened', keys: ['investigate', 'enrich', 'assets'] },
  { name: 'Contain', cap: 'Stop it spreading', keys: ['plan', 'authorize', 'execute'] },
  { name: 'Recover', cap: 'Get back to normal', keys: ['recovery', 'verify', 'report'] },
];
export type PhaseState = 'done' | 'active' | 'pending' | 'failed';
export function phaseState(wf: Step[], keys: string[]): PhaseState {
  const ss = keys.map((k) => wf.find((x) => x.key === k)?.status || 'pending');
  if (ss.every((s) => s === 'done' || s === 'skipped')) return 'done';
  if (ss.includes('failed')) return 'failed';
  if (ss.some((s) => s === 'running' || s === 'done')) return 'active';
  return 'pending';
}

const T: Record<string, (e: EventT) => string> = {
  login_failed: (e) => `Failed sign-in for ${e.user}${e.count && e.count > 1 ? ` (${e.count} tries)` : ''}`,
  login_success: (e) => `${e.user} signed in`,
  privilege_change: (e) => `${e.user} was given more permissions`,
  file_download: (e) => `${e.user} downloaded ${e.resource || 'files'}`,
  file_read: (e) => `${e.user} opened ${e.resource || 'a file'}`,
  file_rename: (e) => `Many files renamed at once on ${e.host}`,
  shadow_copy_deleted: (e) => `Backup copies deleted on ${e.host}`,
  beacon: (e) => `${e.host} contacted a suspicious server`,
  macro_exec: (e) => `A document macro ran on ${e.host}`,
  mailbox_rule_created: (e) => `${e.user} set up a mailbox forwarding rule`,
  iam_attach_policy: () => 'Admin rights attached in the cloud',
  create_access_key: () => 'A new cloud access key was created',
  put_bucket_acl: () => 'Cloud storage was made public',
  stop_logging: () => 'Someone tried to switch off cloud logging',
  lateral_access: (e) => `${e.user} reached another server`,
  email_reported: (e) => `${e.user} reported a suspicious email`,
  email_link_click: (e) => `${e.user} clicked a link in a suspicious email`,
  api_call: (e) => `${e.user || 'A service'} made an API request`,
  outbound_conn: (e) => `${e.host} connected out to ${e.ip || e.domain || 'the internet'}`,
  process_start: (e) => `A program started on ${e.host}`,
  secret_exposed: (e) => `A secret key (${e.resource}) was found in a public code repository`,
  rate_limited: (e) => `Too many requests from ${e.ip}`,
  sql_injection_attempt: () => 'Someone tried to inject database commands through the website',
  db_mass_delete: (e) => `${(e.count || 0).toLocaleString()} records deleted on ${e.host}`,
};
export const evText = (e: EventT) => (T[e.type] ? T[e.type](e) : String(e.type).replace(/_/g, ' '));
export const evMeta = (e: EventT) => [e.ip ? 'from ' + e.ip : '', e.geo ? '(' + e.geo + ')' : '', e.bytes ? (e.bytes / 1e6).toFixed(1) + ' MB' : ''].filter(Boolean).join(' ');
export const SUSP = new Set(['login_failed', 'privilege_change', 'file_rename', 'shadow_copy_deleted', 'beacon', 'macro_exec', 'mailbox_rule_created', 'iam_attach_policy', 'create_access_key', 'put_bucket_acl', 'stop_logging', 'lateral_access', 'email_reported', 'email_link_click', 'secret_exposed', 'rate_limited', 'sql_injection_attempt', 'db_mass_delete']);

export interface ActivityLine { ts: string; tone: 'ok' | 'warn' | 'bad' | 'info'; text: string; incidentId: string }
const short = (t: string, n = 90) => (t.length > n ? t.slice(0, n - 1) + '…' : t);
export function buildActivity(details: Record<string, unknown>[]): ActivityLine[] {
  const out: ActivityLine[] = [];
  for (const i of details as any[]) {
    for (const a of i.alerts || []) out.push({ ts: a.ts, tone: 'bad', incidentId: i.id, text: `Spotted: ${short(a.evidenceSummary || a.category)}` });
    for (const a of i.containment || []) {
      const why = (i.alerts || []).find((x: any) => (a.evidenceRefs || []).some((r: string) => (x.evidence || []).includes(r)))?.evidenceSummary;
      if (a.status === 'executed' && a.executedAt) out.push({ ts: a.executedAt, tone: 'ok', incidentId: i.id, text: `${a.description}${why ? `. Why: ${short(why, 80)}` : ''}${a.approvedBy && !String(a.approvedBy).startsWith('policy') ? ` (you approved)` : ' (handled automatically)'}` });
      if (a.status === 'pending_approval') out.push({ ts: i.updatedAt || new Date().toISOString(), tone: 'warn', incidentId: i.id, text: `Waiting for you: ${a.description}` });
    }
    for (const p of i.approvals || []) if (p.decision === 'rejected') out.push({ ts: p.ts, tone: 'info', incidentId: i.id, text: `You declined: ${p.description}` });
    for (const t of i.recovery?.tasks || []) if (t.status === 'done' && t.completedAt) out.push({ ts: t.completedAt, tone: 'ok', incidentId: i.id, text: `Finished: ${t.title}` });
    if (i.verification) out.push({ ts: i.verification.generatedAt, tone: i.verification.passed ? 'ok' : 'warn', incidentId: i.id, text: i.verification.passed ? 'Double-checked the fix: everything passed' : `Double-checked the fix: ${i.verification.failed} thing(s) still need attention` });
  }
  return out.sort((a, b) => +new Date(b.ts) - +new Date(a.ts));
}

const AREA_LABEL: [string, string][] = [['Accounts', 'users'], ['Servers', 'hosts'], ['Cloud and keys', 'cloud'], ['Data', 'resources']];
export function scoreAreas(details: Record<string, unknown>[]): [string, number][] {
  const pen: Record<string, number> = { users: 0, hosts: 0, cloud: 0, resources: 0 };
  for (const i of details as any[]) {
    if (['RESOLVED', 'CLOSED', 'MONITORING'].includes(i.state)) continue;
    const touched = new Set<string>();
    for (const a of i.alerts || []) {
      const f = a.affected || {};
      if ((f.users || []).length) touched.add('users');
      if ((f.hosts || []).length) touched.add('hosts');
      if ((f.resources || []).length) touched.add('resources');
      if (/cloud|key|secret|token|bucket|iam/i.test(`${a.rule} ${a.category} ${(f.resources || []).join(' ')}`)) touched.add('cloud');
    }
    for (const t of touched) pen[t] += (i.riskScore || 0) / 2;
  }
  return AREA_LABEL.map(([label, k]) => [label, Math.max(0, Math.round(100 - Math.min(70, pen[k])))]);
}
const IF_NO: Record<string, string> = { block_ip: 'The address stays able to reach your systems.', revoke_sessions: 'Anyone already signed in as this person stays signed in.', revoke_token: 'The stolen key keeps working.', restrict_resource: 'The files stay open to anyone who can reach them.', disable_account: 'The account stays active. If it is hacked, the attacker keeps access.', isolate_host: 'The computer stays connected and the problem can spread.', detach_cloud_policy: 'The extra admin rights stay in place.', make_bucket_private: 'The storage stays open to the public.', force_password_reset: 'The old password keeps working.', unblock_ip: 'The address stays blocked.', reenable_account: 'The account stays suspended.' };
export const ifNo = (type?: string) => (type && IF_NO[type]) || 'Nothing changes and the threat is left as it is.';
