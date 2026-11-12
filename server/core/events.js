'use strict';
const { uid } = require('./util');
const bus = require('./bus');

const MAX = 20000;
const store = [];
const SOURCES = ['authentication', 'application', 'system', 'network', 'api', 'file', 'cloud'];
// origin: 'generated' = background demo noise, 'scenario' = scripted attack simulation, 'ingested' = REAL data via /api/ingest
const ORIGINS = ['generated', 'scenario', 'ingested'];

function normalize(raw, origin = 'generated') {
  if (!SOURCES.includes(raw.source)) throw new Error(`invalid source "${raw.source}"`);
  if (!raw.type) throw new Error('event.type required');
  const o = ORIGINS.includes(raw.origin) ? raw.origin : origin;
  return {
    id: raw.id || uid('evt'),
    ts: raw.ts ? new Date(raw.ts).toISOString() : new Date().toISOString(),
    source: raw.source, type: raw.type, origin: o,
    user: raw.user || null, ip: raw.ip || null, device: raw.device || null, host: raw.host || null,
    resource: raw.resource || null, outcome: raw.outcome || null, geo: raw.geo || null,
    bytes: raw.bytes ?? null, count: raw.count ?? null, domain: raw.domain || null, hash: raw.hash || null,
    orgHour: raw.orgHour ?? null, details: raw.details || {},
    scenarioId: raw.scenarioId || null,
  };
}
function add(raw, origin) {
  const e = normalize(raw, origin);
  store.push(e);
  if (store.length > MAX) store.splice(0, store.length - MAX);
  bus.emit('event', e);
  return e;
}
const load = (list) => { store.length = 0; store.push(...list); };
const byId = (id) => store.find((e) => e.id === id);
const byIds = (ids) => { const s = new Set(ids); return store.filter((e) => s.has(e.id)); };
const recent = (n = 100) => store.slice(-n);
const reset = () => { store.length = 0; };

// Map a real AWS CloudTrail record to the PHOENIX event schema (used by POST /api/ingest/cloudtrail).
function fromCloudTrail(r) {
  const map = { AttachRolePolicy: 'iam_attach_policy', AttachUserPolicy: 'iam_attach_policy', CreateAccessKey: 'create_access_key', PutBucketAcl: 'put_bucket_acl', PutBucketPolicy: 'put_bucket_acl', StopLogging: 'stop_logging', DeleteTrail: 'stop_logging', ConsoleLogin: r.responseElements?.ConsoleLogin === 'Success' ? 'login_success' : 'login_failed' };
  const type = map[r.eventName] || 'cloud_api_call';
  return {
    source: type.startsWith('login') ? 'authentication' : 'cloud', type, origin: 'ingested',
    ts: r.eventTime, user: r.userIdentity?.userName || r.userIdentity?.arn || null, ip: r.sourceIPAddress || null,
    resource: r.requestParameters?.bucketName || r.requestParameters?.roleName || r.requestParameters?.name || null,
    outcome: r.errorCode ? 'failure' : 'success',
    details: { eventName: r.eventName, awsRegion: r.awsRegion, policyArn: r.requestParameters?.policyArn, eventID: r.eventID, acl: r.requestParameters?.AccessControlPolicy ? 'public' : undefined },
  };
}
module.exports = { load, add, normalize, byId, byIds, recent, reset, fromCloudTrail, all: () => store, SOURCES };
