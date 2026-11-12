'use strict';
const rz = require('../resilience');
const audit = require('../core/audit');
// ASSISTANT: the chat panel's brain. Commands are understood by fixed rules (no AI service needed, nothing leaves your server).
// It reads the SOC state, answers questions, and runs the same actions as the buttons with the same role checks and audit trail.
// When a request is ambiguous ("unblock sam" and there are two Sams) it asks which one and remembers the question.
// Optional: with ANTHROPIC_API_KEY and PHOENIX_CHAT_LLM=on, questions it cannot answer itself are sent (with a small state summary) to the model
// for a plain-language answer. The model can never execute anything.
const auth = require('../core/auth');
const autonomy = require('../core/autonomy');
const cmd = require('./commander');
const events = require('../core/events');
const sim = require('../sim/enterprise');

const convo = new Map(); // username -> { pending }
const ctxs = new Map(); // username -> last mentioned { ip, user } so "block this ip" works
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const VALID_IP = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const can = (u, role) => auth.allowed(u.role, role);
const deny = (role) => ({ reply: `That needs the **${role}** role. Ask an admin to do it, or to change your role.` });
const isPriv = (ip) => autonomy.isPrivateIp(ip);
const FILLER = /\b(the|a|an|user|users|account|accounts|ip|address|host|please|pls|for|from|of|my|that|this|one|block|blocks|blocked|on|to|and|trust|always|never|again|it)\b/g;
const clean = (t) => t.toLowerCase().replace(/[^a-z0-9@._:\-\s]/g, ' ').replace(FILLER, ' ').replace(/\s+/g, ' ').trim();
const targetStr = (t = {}) => [t.user, t.ip, t.host, t.resource].filter(Boolean).join(' ');
const incIps = (inc) => { try { return [...new Set(JSON.stringify([inc.alerts, inc.title]).match(IPV4) || [])]; } catch { return []; } };
const choicesOf = (opts) => opts.slice(0, 8).map((o, i) => ({ label: `${i + 1}. ${o.label}`, send: String(i + 1) }));

const GLOSSARY = {
  'brute force': 'Many password guesses against one account. PHOENIX flags 5+ failures in 5 minutes (R-BRUTE) and, if one then succeeds, treats the account as compromised.',
  'password spraying': 'One source trying a few common passwords against MANY accounts, to stay under lockout limits. Detected as R-SPRAY.',
  'credential stuffing': 'Trying leaked username/password pairs from other breaches. Looks like many failed logins from one source across many accounts.',
  'mfa': 'Multi-factor authentication: a second proof (app code, key) besides the password. It stops most stolen-password attacks.',
  'phishing': 'A fake message that tricks someone into giving a password or running a file. Report suspicious mail and PHOENIX analyses it without opening links.',
  'ransomware': 'Malware that encrypts files and demands payment. Signs: many files renamed, shadow copies deleted. PHOENIX isolates the host and leaves the rebuild to you.',
  'sql injection': 'Attacker input that changes a database query (quotes, UNION SELECT in a URL). PHOENIX flags these in web logs (R-WEB-INJECT).',
  'xss': 'Cross-site scripting: injecting script into a page other people view. Seen as <script> or onerror= in requests.',
  'waf': 'Web application firewall: blocks malicious web requests at the edge. PHOENIX alerts when it sees many WAF blocks (R-WEB-WAF).',
  'ddos': 'A flood of requests meant to knock a site over. PHOENIX flags request floods (R-WEB-FLOOD); stopping volumetric attacks needs your CDN/WAF.',
  'lateral movement': 'An attacker hopping from one machine to another after getting in.',
  'exfiltration': 'Stealing data out of the network, e.g. a huge download or upload to an unusual place.',
  'siem': 'A system that collects security logs, detects threats and helps respond. PHOENIX X is a small autonomous one.',
  'ioc': 'Indicator of compromise: an IP, domain or file hash linked to an attack.',
  'zero-day': 'A flaw nobody has fixed yet. Rules cannot name it, so PHOENIX leans on behaviour (unusual logins, mass downloads).',
  'privilege escalation': 'Gaining more rights than you should have, e.g. making yourself admin.',
  'session hijacking': 'Stealing a logged-in session or token. PHOENIX flags a token reused from another country (R-TOKEN-REUSE) and revokes it.',
  'beaconing': 'A machine calling home to an attacker at regular intervals (command and control).',
};
const GLOSS_KEY = (t) => { const x = String(t).toLowerCase(); return Object.keys(GLOSSARY).find((k) => x.includes(k) || (k === 'mfa' && /\b(2fa|two.factor)\b/.test(x))); };

function entitiesIn(text) { const ip = (text.match(IPV4) || [])[0] || null; const email = (/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/.exec(text) || [])[0] || null; return { ip, email }; }
const knownUsers = () => { const s = new Set(Object.keys(sim.env?.users || {})); for (const i of cmd.incidents.values()) for (const u of i.entities?.users || []) s.add(u); return [...s]; };
const knownHosts = () => { const s = new Set(Object.keys(sim.env?.hosts || {})); for (const i of cmd.incidents.values()) for (const h of i.entities?.hosts || []) s.add(h); return [...s]; };
function latestExternalIp() { const incs = [...cmd.incidents.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))); for (const i of incs) for (const ip of incIps(i)) if (!isPriv(ip)) return ip; return null; }
function resolveOne(term, list) { const t = term.toLowerCase(); const ex = list.filter((x) => x.toLowerCase() === t); if (ex.length) return ex; const st = list.filter((x) => x.toLowerCase().startsWith(t)); if (st.length) return st; return list.filter((x) => x.toLowerCase().includes(t)); }
const recentEventsFor = (term, n = 8) => { const t = term.toLowerCase(); return events.recent(500).filter((e) => [e.ip, e.user, e.host, e.resource, e.domain].some((v) => v && String(v).toLowerCase().includes(t))).slice(0, n); };
const evLine = (e) => `• ${String(e.ts || '').slice(11, 19)} ${e.source}/${e.type} ${[e.user, e.host, e.ip && '← ' + e.ip, e.path || e.resource].filter(Boolean).join(' ')}`;

async function llmAnswer(text) {
  const key = process.env.ANTHROPIC_API_KEY; if (!key || process.env.PHOENIX_CHAT_LLM !== 'on') return null;
  const open = [...cmd.incidents.values()].slice(-8).map((i) => `${i.id} ${i.title} ${i.severity} ${i.state}`).join('; ');
  const sys = `You are PHOENIX AI inside a security operations console. Answer briefly (under 120 words), plainly, for a non-expert. You can only answer: you cannot execute actions; tell the user the exact chat command to use (e.g. "block 1.2.3.4", "unblock sam", "reset password for bob"). Current state: mode=${autonomy.getMode()}; incidents: ${open || 'none'}; active blocks: ${cmd.containments().length}; pending approvals: ${cmd.pendingFor().length}.`;
  try {
    const r = await fetch((process.env.PHOENIX_API_ANTHROPIC || 'https://api.anthropic.com') + '/v1/messages', { method: 'POST', signal: AbortSignal.timeout(15000), headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5', max_tokens: 400, system: sys, messages: [{ role: 'user', content: text }] }) });
    if (!r.ok) return null; const t = (await r.json()).content?.[0]?.text; return t ? t + '\n\n(AI-generated explanation. Commands I run come from fixed rules.)' : null;
  } catch { return null; }
}

const activeBlocks = () => cmd.containments().map((c) => { const inc = cmd.incidents.get(c.incidentId); return { id: c.id, label: `${c.description}${c.aiAuto ? ' (AI)' : c.incidentId === 'MANUAL' ? ' (manual)' : ''}`, hay: [targetStr(c.target), c.type, c.incidentId, ...(inc ? incIps(inc) : [])].join(' ').toLowerCase(), c }; });
function match(options, term) {
  const t = term.trim(); if (!t) return options;
  const exact = options.filter((o) => o.c && Object.values(o.c.target || {}).some((v) => String(v).toLowerCase() === t)); if (exact.length) return exact; // an exact name/IP beats fuzzy matches
  const toks = t.split(' ').filter(Boolean); return options.filter((o) => toks.every((k) => o.hay.includes(k)));
}
function pickFromPending(p, text) {
  const t = text.toLowerCase().trim(); const n = /^#?(\d{1,2})\b/.exec(t);
  if (n && p.options[+n[1] - 1]) return [p.options[+n[1] - 1]];
  if (/^(all|everything|both|all of them)\b/.test(t)) return p.options;
  if (/^(first|1st|top)\b/.test(t)) return [p.options[0]]; if (/^(second|2nd)\b/.test(t) && p.options[1]) return [p.options[1]]; if (/^(last)\b/.test(t)) return [p.options[p.options.length - 1]];
  const m = match(p.options, clean(t) || t); return m.length ? m : null;
}
async function doUnblock(u, opts, trust) {
  const out = [];
  for (const o of opts) { try { await cmd.undoAction(o.id, u.sub, { trust, reason: 'via chat' }); out.push(`✅ Unblocked **${o.label}**.`); } catch (e) { out.push(`⚠️ Could not unblock ${o.label}: ${e.message}`); } }
  out.push(trust ? 'I will never auto-block these again (trusted).' : 'I will not re-apply these blocks myself for 24 hours. Say "trust …" if you never want them blocked.');
  return { reply: out.join('\n') };
}
async function doDecide(u, opts, approve) {
  const out = [];
  for (const o of opts) { try { await cmd.decide(o.id, approve, u.sub, 'via chat'); out.push(approve ? `✅ Allowed. I'm executing: **${o.label}**.` : `🚫 Disallowed: **${o.label}**. I won't do it.`); } catch (e) { out.push(`⚠️ ${o.label}: ${e.message}`); } }
  return { reply: out.join('\n') };
}
const pendingOptions = () => cmd.pendingFor().filter((p) => p.action).map((p) => ({ id: p.action.id, label: p.action.description, hay: [p.action.description, targetStr(p.action.target), p.action.type, p.incidentId].join(' ').toLowerCase() }));
function stepOptions() {
  const out = [];
  for (const inc of cmd.incidents.values()) { const T = inc.recovery?.tasks || []; for (const t of T) { if (t.status !== 'pending' || !(t.owner === 'human' || t.gate)) continue; if ((t.dependsOn || []).some((d) => !['done', 'skipped'].includes(T.find((x) => x.id === d)?.status))) continue; out.push({ id: t.id, inc: inc.id, label: `${t.title}${t.optional ? ' (optional)' : ''}`, hay: [t.title, t.user, t.host, t.kind, inc.id].join(' ').toLowerCase(), t }); } }
  return out;
}
function statusReply() {
  const open = [...cmd.incidents.values()].filter((i) => !['RESOLVED', 'CLOSED'].includes(i.state));
  const pend = cmd.pendingFor().length, blocks = cmd.containments().length, A = autonomy.status();
  const lines = [`**Mode:** ${A.modes[A.mode].label}  ·  **Open incidents:** ${open.length}  ·  **Waiting for your OK:** ${pend}  ·  **Active blocks:** ${blocks}`];
  for (const i of open.slice(0, 4)) lines.push(`• ${i.id} ${i.title} — ${i.severity || ''} risk ${i.riskScore ?? '?'} (${i.state})`);
  if (!open.length) lines.push('All quiet. I am watching your connected sources.');
  return { reply: lines.join('\n'), choices: [pend ? { label: 'What needs me?', send: 'what needs me' } : null, blocks ? { label: "What's blocked?", send: "what's blocked" } : null].filter(Boolean) };
}
function explain(text) {
  const id = (/INC-\d+/i.exec(text) || [])[0]?.toUpperCase(); const inc = id ? cmd.incidents.get(id) : [...cmd.incidents.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))[0];
  if (!inc) return { reply: id ? `I have no incident ${id}.` : 'No incidents yet.' };
  const done = (inc.recovery?.tasks || []).filter((t) => ['done', 'skipped'].includes(t.status)).length, tot = (inc.recovery?.tasks || []).length;
  return { reply: [`**${inc.id}: ${inc.title}**`, `${inc.severity || ''} · risk ${inc.riskScore ?? '?'} · state ${inc.state}`, `${inc.alerts?.length || 0} alert(s). ${inc.containment?.length || 0} containment action(s): ${(inc.containment || []).map((a) => `${a.type}→${a.status}`).join(', ') || 'none'}.`, `Recovery: ${done}/${tot} steps.`, inc.verification ? `Verification: ${inc.verification.passed ? 'passed' : inc.verification.failed + ' check(s) failed'}.` : ''].filter(Boolean).join('\n') };
}
const HELP = `I run detection → recovery for you. Just tell me, or ask:
• **security check** · **game day** · **brief me** (plain-language incident summary)
• **discover** · **what depends on supabase** · **rehearse supabase** · **verify recovery** · **similar incidents**
• **status** · **what's blocked?** · **what needs me?** · **explain INC-1001**
• **block 203.0.113.9** / **block this ip** · **disable bob** · **reset password for bob** · **isolate ws-bob-01**
• **unblock sam** / **unblock 203.0.113.9** (I ask if several match) · **trust sam** (never auto-block)
• **allow** / **disallow** (pending approvals) · **done** / **skip** / **check** (recovery steps)
• **why was sam blocked?** · **activity for 203.0.113.9** · **who is bob?** · **what is ransomware?**
• **set mode to full|balanced|watch** · **protect ceo@acme.com** · **rotate key <name>** · **rotate all keys** · **check collectors**`;

async function handle(u, raw, opts = {}) {
  const text = String(raw || '').trim().slice(0, 300); if (!text) return { reply: HELP };
  const st = convo.get(u.sub) || {}; const low = text.toLowerCase();
  const ctx = ctxs.get(u.sub) || {}; ctxs.set(u.sub, ctx); const ent = entitiesIn(text); if (ent.ip) ctx.ip = ent.ip; if (ent.email) ctx.user = ent.email;
  if (st.pending?.kind === 'confirm') {
    if (/^(yes|y|yep|yeah|confirm|do it|ok|okay|sure|go ahead)\b/.test(low)) { convo.delete(u.sub); return doManual(u, st.pending.op, st.pending.v, true); }
    if (/^(no|n|nope|cancel|stop|don'?t)\b/.test(low)) { convo.delete(u.sub); return { reply: 'Okay, I did not do it.' }; }
  }
  const fresh = /^(posture|security|game|fire|brief|simple|eli5|blast|rehears|simulate|discover|map |dependency|depends|verify|similar|has this|are we ready|recovery|what if|unblock|unban|trust|approve|allow|deny|reject|disallow|status|help|set|switch|protect|rotate|explain|what|show|list|skip|done|check|cancel|never mind|nevermind|block|ban|disable|suspend|reset|isolate|why|who|activity|revoke)\b/.test(low);
  if (/^(cancel|never ?mind|stop)\b/.test(low)) { convo.delete(u.sub); return { reply: 'Okay, cancelled.' }; }
  // 1) answer to a question I asked
  if (st.pending && st.pending.kind !== 'confirm' && !fresh) {
    const p = st.pending, picked = pickFromPending(p, text);
    if (!picked) return { reply: `I couldn't tell which one you mean. ${p.options.length > 1 ? 'Pick a number, or give a name or IP address.' : ''}`, choices: choicesOf(p.options) };
    if (picked.length > 1 && !/^(all|everything|both)/.test(low)) { convo.set(u.sub, { pending: { ...p, options: picked } }); return { reply: `Still ${picked.length} matches. Which one?`, choices: choicesOf(picked) }; }
    convo.delete(u.sub); return run(u, p.kind, picked, p);
  }
  convo.delete(u.sub);
  // From a chat channel (Telegram/Slack/Discord) anything that needs a human decision is refused and sent to the app.
  if (opts.channel && (/^(approve|allow|deny|reject|disallow|yes|no|ok|okay|go ahead|do it)\b/.test(low) || /^(rotate|protect|trust|never block|always allow|whitelist|done|complete|finished|mark done|i did it|skip|discover|scan|refresh|rebuild|execute|run plan)\b/.test(low) || /\b(set|switch|change|go|use)\b.*\b(watch|balanced|full)\b/.test(low) || /^(watch|balanced|full)( ai)?( mode)?$/.test(low))) {
    const base = (process.env.PHOENIX_PUBLIC_URL || '').replace(/\/$/, ''); audit.log(u.sub, 'CHANNEL_REFUSED', { text: text.slice(0, 60), channel: opts.channel });
    return { reply: `🔒 That needs a human decision, so I won't do it from chat. Open PHOENIX X${base ? ': ' + base + '/#/response' : ''} and press Allow / Disallow there.\nFrom chat I can still: status, what's blocked, block/unblock, explain, rehearse, verify recovery, brief me.` };
  }
  if (/^(help|\?|what can you do|commands)/.test(low)) return { reply: HELP };
  if (/\b(status|summary|what'?s (happening|going on|up)|how are we|any (incidents|threats|alerts))\b/.test(low) && !/blocked|block/.test(low) && !/^(why|who|what is|what are|explain)/.test(low)) return statusReply();
  if (/(what('?s| is| are)|show|list|which).*(blocked|blocks|contained|suspended)|^blocks?$|active blocks/.test(low) && !/^why/.test(low)) { const b = activeBlocks(); const nm = (x) => x.c.target.user || x.c.target.ip || x.c.target.host || x.c.target.resource; return { reply: b.length ? `**${b.length} active block(s):**\n` + b.map((x, i) => `${i + 1}. ${x.label}${x.c.expiresAt ? ' — auto-lifts ' + new Date(x.c.expiresAt).toLocaleString() : ''}`).join('\n') : 'Nothing is blocked right now.', choices: b.slice(0, 4).map((x) => ({ label: 'Unblock ' + nm(x), send: 'unblock ' + nm(x) })) }; }
  if (/(what|anything).*(need|waiting|for me|todo|to do)|pending|next step|what should i do|my tasks/.test(low)) {
    const a = pendingOptions(), s = stepOptions(); if (!a.length && !s.length) return { reply: 'Nothing needs you right now. I am handling it.' };
    return { reply: [a.length ? `**${a.length} action(s) waiting for your OK:**\n` + a.map((x, i) => `${i + 1}. ${x.label}`).join('\n') : '', s.length ? `**${s.length} step(s) for you:**\n` + s.map((x) => `• ${x.label}\n   ${(x.t.how || []).join(' → ')}`).join('\n') : ''].filter(Boolean).join('\n\n'), choices: [a.length ? { label: 'Allow all', send: 'allow all' } : null, a.length ? { label: 'Disallow all', send: 'disallow all' } : null, s.some((x) => x.t.checkable) ? { label: 'Check my steps', send: 'check' } : null].filter(Boolean) };
  }
  let m;
  // ---- application resilience (map, blast radius, rehearsal, verification, memory) ----
  if (/^(?:discover|scan|refresh|rebuild)\b.*\b(map|dependenc|graph|services|providers)|^discover\b/.test(low)) {
    if (!can(u, 'admin')) return deny('admin'); const d = await rz.discover.discoverAll(u.sub); const ok = d.results.filter((x) => x.ok).length;
    return { reply: d.results.length ? `Mapped ${ok}/${d.results.length} connection(s): **${d.summary.nodes} items, ${d.summary.edges} links** (${d.summary.byConfidence.verified || 0} verified, ${d.summary.byConfidence.inferred || 0} inferred).` + d.results.filter((x) => !x.ok).map((x) => `\n⚠️ ${x.name}: ${x.error}`).join('') : 'No provider connections yet. Add Vercel, Render, Supabase, Netlify, Heroku or GitHub on the Connect page.' };
  }
  if ((m = /^(?:blast radius|what depends on|what(?:'s| is) (?:connected|affected)(?: to| by| if)?|dependents of|depends on)\s*(?:of|for)?\s*(.+?)\??$/.exec(low)) || (m = /^what depends on\s+(.+?)\??$/.exec(low))) {
    const hit = rz.graph.find(m[1]); if (!hit.length) return { reply: `I have no "${m[1]}" in the dependency map. Say **discover** to refresh it.` };
    const b = rz.blast.compute([hit[0].id]); return { reply: b.counts.total ? `**Blast radius of ${hit[0].name}**: ${b.counts.total} item(s) (${b.counts.verified} verified, ${b.counts.inferred} inferred)\n• Services to redeploy: ${b.connectedDeployments.join(', ') || 'none'}\n• Variables that may hold it: ${b.exposedSecrets.join(', ') || 'none'}\n• Downstream: ${b.downstream.join(', ') || 'none'}${b.caveat ? '\n⚠️ ' + b.caveat : ''}` : `Nothing in the map depends on ${hit[0].name}.` };
  }
  if ((m = /^(?:rehearse|simulate|what if|rehearsal)\s*(?:a |an |the )?(?:compromise of |compromised |leak of |leaked )?(.+?)(?: (?:is|was|were|gets?) (?:compromised|leaked|stolen|hacked))?\??$/.exec(low)) && !/^(ready|readiness)$/.test(m[1])) {
    if (!can(u, 'analyst')) return deny('analyst'); const t = m[1].replace(/\b(api )?(key|token|account)s?\b/g, '').trim() || m[1]; const hit = rz.graph.find(t); const prov = ['vercel', 'render', 'netlify', 'heroku', 'supabase'].find((x) => t === x);
    if (!hit.length && !prov) return { reply: `I can't find "${m[1]}" in the dependency map. Say **discover** first.` };
    const r = await rz.rehearse.run({ scenario: prov && !hit.length ? 'provider' : hit[0].type === 'repo' ? 'repo' : 'credential', target: prov && !hit.length ? prov : hit[0].id, by: u.sub });
    return { reply: `**Rehearsal (nothing was changed): ${r.scenarioLabel}**\nReadiness **${r.score}/100 — ${r.verdict.replace('_', ' ')}**. ${r.blast.counts.total} item(s) affected; recovery needs ~${r.estimate.steps} steps (${r.estimate.automatedSteps} done by me, ${r.estimate.humanSteps} by you), about ${r.estimate.minutes} min.${r.missing.length ? '\n**Missing:** ' + r.missing.map((x) => x.label + ' (' + x.detail.slice(0, 90) + ')').join('; ') : '\nNo gaps found.'}` };
  }
  if (/^(?:are we|am i|is (?:it|everything)) ready|recovery readiness|^readiness\b/.test(low)) {
    const h = rz.rehearse.history(1)[0]; if (!h) return { reply: 'I have not rehearsed a recovery yet. Try **rehearse supabase** (or any service name).' };
    return { reply: `Last rehearsal (${h.scenarioLabel}): **${h.score}/100 — ${h.verdict.replace('_', ' ')}**, ${h.affected} item(s) affected. Open the Resilience page for the missing requirements.` };
  }
  if (/^(?:verify|run verification|check) (?:the )?(?:recovery|app|checks?)|^run (?:the )?(?:recovery )?(?:verification|checks)/.test(low)) {
    if (!can(u, 'analyst')) return deny('analyst'); const r = await rz.verify.run({ by: u.sub }); if (r.verdict === 'NO_CHECKS') return { reply: 'No verification checks are defined yet. Add some on the Resilience page (health endpoint, old key rejected).' };
    return { reply: `Verification **${r.verdict.replace(/_/g, ' ')}**: ${r.passed}/${r.total} checks passed.` + r.results.filter((x) => !x.ok).map((x) => `\n❌ ${x.name}: ${x.detail}`).join('') };
  }
  if (/^(?:posture|security (?:check|scan|audit)|scan (?:my )?(?:app|posture|security)|am i exposed|find weaknesses)\b/.test(low)) {
    if (!can(u, 'analyst')) return deny('analyst'); const r = await rz.posture.run(u.sub); const top = r.findings.filter((f) => f.severity !== 'info').slice(0, 4);
    return { reply: `**Security posture ${r.score}/100** (${r.counts.critical || 0} critical, ${r.counts.high || 0} high, ${r.counts.medium || 0} medium).` + (top.length ? '\n' + top.map((f) => `• [${f.severity}] ${f.title} (${f.where})\n   Fix: ${f.fix}`).join('\n') : '\nNo weaknesses found in what I can check.') };
  }
  if (/^(?:game ?day|run (?:a )?(?:game ?day|fire ?drill)|fire ?drill)\b/.test(low)) {
    if (!can(u, 'analyst')) return deny('analyst'); const r = await rz.gameday.run(u.sub); if (r.score == null) return { reply: 'Nothing to rehearse yet. Connect providers and discover your services first.' };
    return { reply: `**Game day: readiness ${r.score}/100**${r.delta != null ? ` (${r.delta >= 0 ? '+' : ''}${r.delta} since last time)` : ''}. ${r.notReady} scenario(s) not ready.${r.worst ? ` Weakest: ${r.worst.label} (${r.worst.score}).` : ''}` };
  }
  if (/^(?:brief me|explain (?:it )?(?:simply|like|in plain)|in plain (?:english|words)|simple summary|eli5|what do i (?:do|need to do))\b/.test(low)) {
    const id = (/INC-\d+/i.exec(text) || [])[0]?.toUpperCase(); const inc = id ? cmd.incidents.get(id) : [...cmd.incidents.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))[0];
    if (!inc) return { reply: 'No incidents yet. All quiet.' }; return { reply: rz.brief.text(rz.brief.briefing(inc)) };
  }
  if (/^(?:similar|has this (?:happened|occurred)|have we seen this|past incidents?|history of this)/.test(low)) {
    const inc = [...cmd.incidents.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))[0]; if (!inc) return { reply: 'No incidents yet.' };
    const sm = rz.memory.similar(inc); return { reply: sm.length ? `${inc.id} resembles earlier incidents:\n` + sm.map((x) => `• ${x.incidentId} (${x.similarity}% similar${x.verified ? ', recovery verified' : ''}): what worked: ${x.procedure.join('; ') || 'n/a'}`).join('\n') : `I have no similar earlier incident for ${inc.id}.` };
  }
  if (/^rotate\s+all\s+(?:the\s+)?(?:api\s+|ingest\s+)?keys/.test(low)) { if (!can(u, 'admin')) return deny('admin'); convo.set(u.sub, { pending: { kind: 'confirm', op: 'rotate_all', v: 'all' } }); return { reply: 'Rotate **all** ingest keys? Every connected platform stops sending until you paste its new key. Say **yes** to confirm.', choices: [{ label: 'Yes, rotate all', send: 'yes' }, { label: 'Cancel', send: 'cancel' }] }; }
  if ((m = /^(?:please\s+)?(?:block|ban|blacklist)\s+(.*)$/.exec(low)) || (m = /^(?:please\s+)?deny\s+(.*\bip\b.*)$/.exec(low))) {
    if (!can(u, 'analyst')) return deny('analyst');
    const rest = m[1]; let ip = ent.ip, inferred = false;
    if (!ip && /^(it|this|that|the|attacker|last)\b/.test(rest) && !/@/.test(rest)) { ip = ctx.ip || latestExternalIp(); inferred = true; }
    if (ip && !VALID_IP.test(ip)) return { reply: `${ip} is not a valid IPv4 address.` };
    if (ip) { ctx.ip = ip; const r = await doManual(u, 'block_ip', ip, !isPriv(ip)); if (inferred) r.reply = `(Using ${ip}, from our conversation or the latest incident.)\n` + r.reply; return r; }
    if (inferred) return { reply: 'I do not have an IP address to block yet. Say **block 203.0.113.9**.' };
    return userTarget(u, 'disable', clean(rest) || rest, ctx);
  }
  if ((m = /^(?:disable|suspend|lock(?: out)?|deactivate)\s+(?:the\s+)?(?:user\s+|account\s+)?(.+)/.exec(low))) return userTarget(u, 'disable', clean(m[1]) || m[1], ctx);
  if ((m = /^(?:reset|force|expire)\s+(?:the\s+)?(?:password|credentials|pw)\s*(?:reset\s*)?(?:for|of)?\s*(.+)/.exec(low))) return userTarget(u, 'reset', clean(m[1]) || m[1], ctx);
  if ((m = /^(?:revoke|kill|end)\s+(?:all\s+)?(?:the\s+)?sessions?\s*(?:for|of)?\s*(.+)/.exec(low)) || (m = /^(?:log ?out|sign ?out)\s+(.+)/.exec(low))) return userTarget(u, 'revoke', clean(m[1]) || m[1], ctx);
  if ((m = /^(?:isolate|quarantine)\s+(?:the\s+)?(?:host\s+)?(.+)/.exec(low))) { const term = clean(m[1]) || m[1]; const hs = resolveOne(term, knownHosts()); if (hs.length > 1) { const opts = hs.map((x) => ({ id: x, label: x, hay: x.toLowerCase() })); convo.set(u.sub, { pending: { kind: 'target', op: 'isolate', options: opts } }); return { reply: `Which host? (${hs.length} matches)`, choices: choicesOf(opts) }; } return doManual(u, 'isolate', hs[0] || term, false); }
  if ((m = /^why\b(.*)$/.exec(low))) {
    const term = clean(m[1].replace(/\b(was|were|is|are|did|do|you|we|have|has|been|blocked|suspended|disabled|isolated|banned|contained|block|suspend|disable|isolate|ban|contain)\b/g, ' ')); const hits = [];
    for (const inc of cmd.incidents.values()) for (const a of inc.containment || []) if (!term || (targetStr(a.target) + ' ' + incIps(inc).join(' ')).toLowerCase().includes(term)) hits.push({ inc, a });
    for (const a of cmd.manualList()) if (!term || targetStr(a.target).toLowerCase().includes(term)) hits.push({ inc: null, a });
    if (!hits.length) return { reply: term ? `I have no record of acting on "${term}".` : 'I have not taken any actions yet.' };
    return { reply: hits.slice(0, 4).map(({ inc, a }) => `**${a.description}** (${a.status}${a.aiAuto ? ', done by the AI' : a.manual ? ', requested by ' + a.requestedBy : ''})\n${inc ? `Because of ${inc.id} "${inc.title}": ${[...new Set((inc.alerts || []).map((x) => x.rule))].join(', ')}.\n` : ''}Reason: ${a.rationale || a.reason || a.policyReason || 'n/a'}`).join('\n\n') };
  }
  if ((m = /^(?:show\s+|get\s+|find\s+)?(?:me\s+)?(?:the\s+)?(?:recent\s+)?(?:activity|events?|logs?|history)\s*(?:for|of|from|on|about|with)?\s*(.*)$/.exec(low)) || (m = /^what happened (?:with|to|on|from)\s+(.+)/.exec(low))) {
    const term = ent.ip || ent.email || clean(m[1]); if (!term) return { reply: 'Whose activity? Try **activity for 203.0.113.9** or **activity for bob**.' }; const ev = recentEventsFor(term);
    return { reply: ev.length ? `**Latest ${ev.length} event(s) for ${term}:**\n` + ev.map(evLine).join('\n') : `No recent events mention "${term}".` };
  }
  if ((m = /^(?:who is|who'?s|tell me about|info (?:on|about)|details (?:on|for|about)|show me)\s+(?:the\s+)?(?:user\s+|host\s+|ip\s+)?(.+?)\??$/.exec(low)) && !GLOSS_KEY(m[1]) && !/^(me|status|incidents?|blocks?)$/.test(m[1])) {
    const term = ent.ip || ent.email || clean(m[1]); const rel = [...cmd.incidents.values()].filter((i) => JSON.stringify([i.entities, i.title]).toLowerCase().includes(term.toLowerCase()));
    const bl = activeBlocks().filter((b) => b.hay.includes(term.toLowerCase())), ev = recentEventsFor(term, 3), pr = autonomy.isProtected({ user: term, ip: term, host: term });
    const su = sim.env?.users?.[term]; if (!rel.length && !bl.length && !ev.length && !su) return { reply: `I have nothing on "${term}" yet.` };
    return { reply: [`**${term}**${su ? ` — ${su.dept || ''} ${su.role || ''}, account ${su.status}` : ''}${pr ? ' · 🛡️ protected' : ''}`, rel.length ? `Incidents: ${rel.map((i) => `${i.id} (${i.severity || ''} ${i.state})`).join(', ')}` : 'No incidents.', bl.length ? `Currently blocked: ${bl.map((b) => b.label).join('; ')}` : 'Not blocked.', ev.length ? `Latest activity:\n${ev.map(evLine).join('\n')}` : ''].filter(Boolean).join('\n') };
  }
  if (/^(?:list|show)\s+(?:all\s+|the\s+)?(?:open\s+)?(?:incidents|alerts|threats)|^incidents?$/.test(low)) { const l = [...cmd.incidents.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, 10); return { reply: l.length ? l.map((i) => `• ${i.id} ${i.title} — ${i.severity || ''} risk ${i.riskScore ?? '?'} (${i.state})`).join('\n') : 'No incidents yet.', choices: l.slice(0, 3).map((i) => ({ label: 'Explain ' + i.id, send: 'explain ' + i.id })) }; }
  if (/\b(how (safe|secure|risky)|risk (level|score)|security posture|are we (ok|safe|secure))\b/.test(low)) { const open = [...cmd.incidents.values()].filter((i) => !['RESOLVED', 'CLOSED'].includes(i.state)); const top = open.reduce((x, i) => Math.max(x, i.riskScore || 0), 0); return { reply: open.length ? `${open.length} open incident(s), highest risk ${top}/100. ${cmd.containments().length} active block(s). ${cmd.pendingFor().length ? cmd.pendingFor().length + ' action(s) need your OK.' : 'Nothing waits for you.'}` : 'Nothing open. No active threats right now.' }; }
  if ((m = /^(?:what is|what'?s|what are|whats|explain|define|meaning of|tell me about)\s+(?:a |an |the )?(.+?)\??$/.exec(low)) && GLOSS_KEY(m[1])) return { reply: `**${GLOSS_KEY(m[1])}**: ${GLOSSARY[GLOSS_KEY(m[1])]}` };
  if ((m = /^(?:set|switch|change|go|use|turn)?\s*(?:the )?(?:ai )?(?:mode )?(?:to )?(watch|balanced|full)(?: ai)?(?: mode)?\s*$/.exec(low)) || (m = /\b(?:set|switch|change|go|use)\b.*\b(watch|balanced|full)\b/.exec(low))) {
    if (!can(u, 'admin')) return deny('admin'); autonomy.setMode(m[1], u.sub); return { reply: `Mode is now **${autonomy.status().modes[m[1]].label}**. ${autonomy.status().modes[m[1]].blurb}` };
  }
  if ((m = /^(?:trust|never block|always allow|whitelist)\s+(.+)/.exec(low)) && !/^(all)$/.test(m[1])) {
    if (!can(u, 'admin')) return deny('admin'); const term = clean(m[1]); const opts = match(activeBlocks(), term);
    if (opts.length) return pick(u, 'unblock', opts, term, { trust: true });
    const v = m[1].trim(); const kind = VALID_IP.test(v) ? 'ip' : 'user';
    const e = autonomy.protect({ kind, value: v, reason: 'trusted via chat' }, u.sub); return { reply: `🛡️ **${e.value}** is now protected: the AI will never auto-block it.` };
  }
  if ((m = /^protect\s+(.+)/.exec(low))) { if (!can(u, 'admin')) return deny('admin'); const v = m[1].trim(); const kind = VALID_IP.test(v) ? 'ip' : 'user'; const e = autonomy.protect({ kind, value: v, reason: 'protected via chat' }, u.sub); return { reply: `🛡️ **${e.value}** (${e.kind}) is protected from automatic blocking.` }; }
  if ((m = /^(?:unblock|unban|unsuspend|re-?enable|lift|release|restore access(?: for| to)?|undo)\b\s*(.*)/.exec(low))) {
    if (!can(u, 'analyst')) return deny('analyst'); const term = clean(m[1]); const all = activeBlocks();
    if (!all.length) return { reply: 'Nothing is blocked right now.' };
    const everything = /^(everything|all)$/.test(term); const opts = term && !everything ? match(all, term) : all;
    if (term && !everything && !opts.length) return { reply: `I couldn't find anything blocked that matches "${term}". Currently blocked:\n` + all.map((x, i) => `${i + 1}. ${x.label}`).join('\n'), choices: choicesOf(all) };
    return pick(u, 'unblock', opts, term, { trust: /\btrust\b/.test(low), all: everything });
  }
  if ((m = /^(approve|allow|yes|ok|okay|go ahead|do it|deny|reject|disallow|no|don'?t)\b\s*(.*)/.exec(low))) {
    if (!can(u, 'admin')) return deny('admin'); const approve = /^(approve|allow|yes|ok|okay|go ahead|do it)/.test(m[1]); const opts = pendingOptions(), steps = stepOptions().filter((x) => x.t.gate);
    const all = [...opts, ...steps]; if (!all.length) return { reply: 'Nothing is waiting for your decision.' };
    const term = clean(m[2]); const sel = /^(all|everything)$/.test(term) ? all : term ? match(all, term) : all;
    if (term && !sel.length) return { reply: `Nothing waiting matches "${term}".`, choices: choicesOf(all) };
    return pick(u, approve ? 'approve' : 'disapprove', sel, term, { all: /^(all|everything)$/.test(term) });
  }
  if (/^(check|verify|recheck|re-check)\b/.test(low)) {
    if (!can(u, 'analyst')) return deny('analyst'); const all = stepOptions().filter((x) => x.t.checkable); if (!all.length) return { reply: 'No waiting step can be verified automatically. Press Done when you finish a step.' };
    const out = []; for (const o of all) { try { const r = await cmd.checkTask(o.inc, o.id, u.sub); out.push(r.done ? `✅ ${o.label}: verified, moving on.` : `⏳ ${o.label}: ${r.detail}`); } catch (e) { out.push(`⚠️ ${o.label}: ${e.message}`); } }
    return { reply: out.join('\n') };
  }
  if ((m = /^(done|complete|finished|mark done|i did it|skip|skip step|skip it)\b\s*(.*)/.exec(low))) {
    if (!can(u, 'analyst')) return deny('analyst'); const skip = /^skip/.test(m[1]); const all = stepOptions().filter((x) => (skip ? x.t.optional || x.t.gate : x.t.owner === 'human'));
    if (!all.length) return { reply: skip ? 'No optional steps are waiting. Required steps cannot be skipped.' : 'No steps are waiting for you.' };
    const term = clean(m[2]); const sel = term ? match(all, term) : all; if (term && !sel.length) return { reply: `No step matches "${term}".`, choices: choicesOf(all) };
    return pick(u, skip ? 'skip' : 'done', sel, term, {});
  }
  if ((m = /^rotate\s+(?:the |my )?(?:api |ingest )?key\s*(.*)/.exec(low))) {
    if (!can(u, 'admin')) return deny('admin'); const keys = auth.listKeys().filter((k) => !k.disabled).map((k) => ({ id: k.id, label: `${k.name} (${k.format})`, hay: (k.name + ' ' + k.format + ' ' + k.id).toLowerCase() }));
    if (!keys.length) return { reply: 'There are no active ingest keys.' }; const term = clean(m[1]); const sel = term ? match(keys, term) : keys;
    if (!sel.length) return { reply: `No key matches "${term}".`, choices: choicesOf(keys) }; return pick(u, 'rotate', sel, term, {});
  }
  if (/INC-\d+/i.test(text) || /^explain\b.*\b(incident|latest|last)\b|^(latest|last) incident/.test(low)) return explain(text);
  if (/collector|poll|pull/.test(low)) { if (!can(u, 'admin')) return deny('admin'); const c = require('../collectors').list(); return { reply: c.length ? c.map((x) => `• ${x.name}: ${x.status}${x.error ? ' (' + x.error + ')' : ''}, ${x.totalEvents} events`).join('\n') : 'No collectors connected yet. Use Connect a Platform → "Connect with an API token".' }; }
  const llm = await llmAnswer(text); if (llm) return { reply: llm };
  return { reply: `I didn't understand that. ${HELP}` };
}
// find the user a command refers to (asks which one when several match), then act
async function userTarget(u, op, term, ctx) {
  if (/^(him|her|them|it|this user|that user|this account|that account|this|that|)$/.test(term)) term = ctx.user || '';
  if (!term) return { reply: 'Which user? Say for example **' + (op === 'disable' ? 'disable bob' : op === 'reset' ? 'reset password for bob' : 'revoke sessions for bob') + '**.' };
  const us = term.includes('@') ? [term] : resolveOne(term, knownUsers());
  if (us.length > 1) { const opts = us.map((x) => ({ id: x, label: x, hay: x.toLowerCase() })); convo.set(u.sub, { pending: { kind: 'target', op, options: opts } }); return { reply: `**${us.length}** users match "${term}". Which one?`, choices: choicesOf(opts) }; }
  ctx.user = us[0] || term; return doManual(u, op, us[0] || term, false);
}
const SPEC = {
  block_ip: (v) => ({ type: 'block_ip', target: { ip: v }, role: 'analyst', label: `Block ${v}`, undo: v }),
  disable: (v) => ({ type: 'disable_account', target: { user: v }, role: 'admin', confirm: true, label: `Suspend account ${v}`, undo: v }),
  reset: (v) => ({ type: 'force_password_reset', target: { user: v }, role: 'admin', label: `Force a password reset for ${v}` }),
  revoke: (v) => ({ type: 'revoke_sessions', target: { user: v }, role: 'analyst', label: `Revoke all sessions for ${v}` }),
  isolate: (v) => ({ type: 'isolate_host', target: { host: v }, role: 'admin', confirm: true, label: `Isolate host ${v}`, undo: v }),
};
async function doManual(u, op, v, noConfirm) {
  if (op === 'rotate_all') { if (!can(u, 'admin')) return deny('admin'); const ks = auth.rotateAll(u.sub); return { reply: ks.length ? `🔑 Rotated **${ks.length}** key(s). New keys (shown once, copy them now):\n` + ks.map((k) => `• ${k.name}: \`${k.key}\``).join('\n') : 'There were no active keys.' }; }
  const s = SPEC[op]?.(v); if (!s) return { reply: 'Unknown operation.' }; if (!can(u, s.role)) return deny(s.role);
  if ((s.confirm || (op === 'block_ip' && isPriv(v))) && !noConfirm) { convo.set(u.sub, { pending: { kind: 'confirm', op, v } }); return { reply: `${s.label}?${op === 'block_ip' ? ' That is an internal address; blocking it may cut off your own network.' : ''} Say **yes** to confirm.`, choices: [{ label: 'Yes, do it', send: 'yes' }, { label: 'Cancel', send: 'cancel' }] }; }
  try {
    const r = await cmd.manualAction(s.type, s.target, u.sub, 'via chat');
    if (r.status === 'executed') return { reply: `✅ Done: **${s.label}**.${s.undo ? ' Say "unblock ' + s.undo + '" to undo it.' : ''}`, choices: s.undo ? [{ label: 'Undo', send: 'unblock ' + s.undo }] : [] };
    if (r.status === 'dry_run') return { reply: '🧪 The connector is in **dry-run**, so nothing was changed. Turn dry-run off (PHOENIX_CONNECTOR_DRYRUN=off) when you trust it.' };
    if (r.status === 'manual_required') return { reply: `⚠️ I can't do this myself: no connector is configured for it. ${r.detail || ''}\nDo it in your own console; I've logged the request.` };
    return { reply: `❌ ${r.detail || r.error || 'It did not work.'}` };
  } catch (e) { return { reply: `⚠️ ${e.message}` }; }
}
// one match → do it; many → ask which
function pick(u, kind, opts, term, extra) {
  if (opts.length === 1 || extra.all) return run(u, kind, opts, extra);
  convo.set(u.sub, { pending: { kind, options: opts, ...extra } });
  const who = term ? ` for "${term}"` : '';
  return { reply: `I found **${opts.length}** matches${who}. Which one?${kind === 'unblock' ? ' (You can answer with a number, a name, or an IP address.)' : ''}`, choices: [...choicesOf(opts), ...(opts.length > 1 ? [{ label: 'All of them', send: 'all' }] : [])] };
}
async function run(u, kind, picked, extra = {}) {
  const trust = !!extra.trust;
  if (kind === 'unblock') return doUnblock(u, picked, trust);
  if (kind === 'target') return doManual(u, extra.op, picked[0].id, false);
  if (kind === 'approve' || kind === 'disapprove') {
    const gated = picked.filter((o) => o.t), acts = picked.filter((o) => !o.t); const outs = [];
    if (acts.length) outs.push((await doDecide(u, acts, kind === 'approve')).reply);
    for (const g of gated) { try { if (kind === 'approve') await cmd.completeTask(g.inc, g.id, u.sub); else await cmd.skipTask(g.inc, g.id, u.sub); outs.push(kind === 'approve' ? `✅ Allowed. I'm doing: **${g.label}**.` : `🚫 Disallowed: **${g.label}**.`); } catch (e) { outs.push('⚠️ ' + e.message); } }
    return { reply: outs.join('\n') };
  }
  if (kind === 'done' || kind === 'skip') { const outs = []; for (const o of picked) { try { if (kind === 'done') await cmd.completeTask(o.inc, o.id, u.sub); else await cmd.skipTask(o.inc, o.id, u.sub); outs.push(`${kind === 'done' ? '✅ Marked done' : '⏭️ Skipped'}: ${o.label}`); } catch (e) { outs.push('⚠️ ' + e.message); } } outs.push('I will continue from here.'); return { reply: outs.join('\n') }; }
  if (kind === 'rotate') { const outs = []; for (const o of picked) { try { const n = auth.rotateKey(o.id, u.sub); outs.push(`🔑 Rotated **${o.label}**. New key (shown once, copy it now):\n\`${n.key}\`\nThe old key no longer works. Update your platform with the new one.`); } catch (e) { outs.push('⚠️ ' + e.message); } } return { reply: outs.join('\n') }; }
  return { reply: 'Done.' };
}
const reset = () => { convo.clear(); ctxs.clear(); };
module.exports = { handle, reset };
