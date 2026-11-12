'use strict';
// ORACLE — Threat Intelligence Agent.
// Tools: VirusTotal v3 REST (if VT_API_KEY set) -> otherwise a clearly-labelled local SAMPLE database (fictional indicators).
// Rule: an indicator that is simply not recognised is verdict "unknown" — never "malicious".
const { sha256 } = require('../core/util');
const { validate, SPECS } = require('../core/schema');

const H_DROPPER = sha256('phx-sim-macro-dropper'), H_LOCKER = sha256('phx-sim-phoenixlock-ransomware');
const LOCAL = {
  ip: {
    '198.19.66.14': { verdict: 'malicious', confidence: 0.9, tags: ['credential-stuffing', 'botnet'], detail: 'Sample DB: source of large-scale credential-stuffing campaigns' },
    '198.19.66.77': { verdict: 'malicious', confidence: 0.95, tags: ['c2', 'ransomware'], detail: 'Sample DB: PhoenixLock-sim ransomware command-and-control server' },
    '198.19.99.5': { verdict: 'suspicious', confidence: 0.5, tags: ['anonymizing-proxy'], detail: 'Sample DB: commercial VPN/proxy exit node (not inherently malicious)' },
    '198.19.88.23': { verdict: 'malicious', confidence: 0.85, tags: ['phishing-kit', 'token-replay'], detail: 'Sample DB: hosts adversary-in-the-middle phishing kit' },
  },
  domain: {
    'secure-payroll-login.example': { verdict: 'malicious', confidence: 0.92, tags: ['phishing', 'lookalike'], detail: 'Sample DB: payroll-portal lookalike harvesting credentials' },
    'updates.vendor-ok.example': { verdict: 'no_detections', confidence: 0.6, tags: [], detail: 'Sample DB: known vendor update domain' },
  },
  hash: {
    [H_DROPPER]: { verdict: 'malicious', confidence: 0.9, tags: ['macro-dropper', 'loader'], detail: 'Sample DB: VBA macro dropper family' },
    [H_LOCKER]: { verdict: 'malicious', confidence: 0.97, tags: ['ransomware', 'phoenixlock-sim'], detail: 'Sample DB: PhoenixLock-sim ransomware payload' },
  },
};
const cache = new Map();
const hasVT = () => !!process.env.VT_API_KEY;

async function vt(type, value) {
  const path = { ip: 'ip_addresses', domain: 'domains', hash: 'files' }[type];
  const r = await fetch(`https://www.virustotal.com/api/v3/${path}/${encodeURIComponent(value)}`, { headers: { 'x-apikey': process.env.VT_API_KEY }, signal: AbortSignal.timeout(8000) });
  if (r.status === 404) return { verdict: 'unknown', confidence: 0, tags: [], detail: 'VirusTotal has no record of this indicator (NOT evidence it is safe or malicious)' };
  if (!r.ok) throw new Error(`VirusTotal HTTP ${r.status}`);
  const a = (await r.json()).data?.attributes || {};
  const s = a.last_analysis_stats || {};
  const mal = s.malicious || 0, sus = s.suspicious || 0;
  const verdict = mal >= 3 ? 'malicious' : mal >= 1 || sus >= 2 ? 'suspicious' : (s.harmless || 0) > 0 ? 'no_detections' : 'unknown';
  return { verdict, confidence: Math.min(1, (mal + sus / 2) / 15), tags: a.tags || [], detail: `VirusTotal: ${mal} malicious / ${sus} suspicious / ${s.harmless || 0} harmless engines` };
}

async function lookup(type, value) {
  const k = type + ':' + value;
  if (cache.has(k)) return cache.get(k);
  let res, live = false, source = 'local-sample-db', error = null;
  if (hasVT()) { try { res = await vt(type, value); live = true; source = 'virustotal'; } catch (e) { error = e.message; } }
  if (!res) res = LOCAL[type]?.[value] || { verdict: 'unknown', confidence: 0, tags: [], detail: 'Not present in local sample database (NOT evidence of safety or malice)' };
  const out = { indicator: value, type, ...res, source, live, error, queriedAt: new Date().toISOString() };
  cache.set(k, out); return out;
}

// indicators: {ips:[], domains:[], hashes:[]}
async function enrich(ind, { internalIp = (ip) => /^(10\.|192\.168\.)/.test(ip) } = {}) {
  const list = [];
  for (const ip of new Set(ind.ips || [])) if (ip && !internalIp(ip)) list.push(['ip', ip]);
  for (const d of new Set(ind.domains || [])) if (d) list.push(['domain', d]);
  for (const h of new Set(ind.hashes || [])) if (h) list.push(['hash', h]);
  const indicators = await Promise.all(list.map(([t, v]) => lookup(t, v)));
  const mal = indicators.filter((i) => i.verdict === 'malicious'), unk = indicators.filter((i) => i.verdict === 'unknown');
  const patterns = [...new Set(indicators.flatMap((i) => i.tags))];
  const out = { indicators, relatedPatterns: patterns, summary: `${indicators.length} indicators checked via ${hasVT() ? 'VirusTotal (live)' : 'local SAMPLE database (no VT_API_KEY configured)'}: ${mal.length} known-malicious, ${unk.length} unknown (not treated as malicious).` };
  const v = validate(SPECS.intel, out, 'intel'); if (!v.ok) throw new Error(v.errors.join(';'));
  return out;
}
module.exports = { enrich, lookup, hashes: { dropper: H_DROPPER, locker: H_LOCKER }, hasVT };
