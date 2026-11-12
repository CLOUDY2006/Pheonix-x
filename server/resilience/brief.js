'use strict';
// PLAIN-LANGUAGE BRIEFING: explains an incident to a non-expert in five short parts. Deterministic (no AI guesswork): it only restates
// what the incident record contains.
const MEANING = {
  'Credential Exposure': 'A secret key was exposed. Anyone who finds it could act as your app, so it must be replaced.',
  'Credential Access': 'Someone tried to get or use account credentials. If they succeed they can sign in as a real user.',
  'Initial Access': 'Someone may have got into an account or system they should not have.',
  'Data Exposure': 'Data or code may be visible to people who should not see it.',
  'Persistence': 'Someone may have created a way to come back later (a new key, user or rule).',
  'Impact': 'Files or services may be damaged or locked.',
  'Exfiltration': 'Data may be leaving your systems.',
  'Blocked Attack Traffic': 'Your site is being probed or attacked from the internet. Your firewall blocked it.',
};
const KEYWORDS = [[/brute|stuffing|failed login/i, 'Someone is guessing passwords. If one guess works they get into a real account.'], [/token|session/i, 'A sign-in token was reused from somewhere unexpected, which can let someone in without the password.'], [/phish|email/i, 'A deceptive message may have tricked someone into giving away a login.'], [/ransom|encrypt|shadow/i, 'Files may be getting locked or backups destroyed.'], [/exfil|collection|bulk|download/i, 'Data may be copied out of your systems.'], [/lateral|privilege|admin/i, 'An account may be gaining more access than it should have.'], [/mailbox|forward/i, 'Someone may be quietly reading or forwarding mail.']];
const plainAction = (a) => `${a.description || a.type}${a.aiAuto ? ' (done by the AI)' : ''}`;
function briefing(inc) {
  const al = inc.alerts || [], cat = al[0]?.category, acts = inc.containment || [], tasks = inc.recovery?.tasks || [];
  const done = acts.filter((a) => ['executed', 'completed'].includes(a.status)), wait = acts.filter((a) => a.status === 'pending_approval');
  const youTasks = tasks.filter((t) => t.owner === 'human' && !['done', 'skipped'].includes(t.status) && !t.optional);
  const steps = [...wait.map((a) => `Open PHOENIX X and press Allow or Disallow: ${a.description || a.type}`), ...youTasks.map((t) => t.title), ...(inc.leak?.planId ? [`Review recovery plan ${inc.leak.planId} and approve it (App Resilience → Safe recovery)`] : [])];
  const sev = inc.severity || 'unknown', urgent = ['critical', 'high'].includes(sev);
  return {
    incident: inc.id, severity: sev, urgent,
    headline: `${urgent ? 'Needs attention: ' : ''}${inc.title}`,
    whatHappened: al.slice(0, 3).map((a) => a.evidenceSummary).filter(Boolean),
    whyItMatters: [...new Set(al.flatMap((a) => [MEANING[a.category], (KEYWORDS.find(([re]) => re.test(`${a.category} ${a.rule} ${a.evidenceSummary}`)) || [])[1]]).filter(Boolean))].slice(0, 2).join(' ') || 'This activity is unusual for your environment.',
    alreadyDone: done.map(plainAction), waitingOnYou: steps.slice(0, 5),
    doNow: (steps.length ? steps : ['Nothing is needed from you right now. PHOENIX X is handling it.']).slice(0, 3),
    affected: inc.blast ? `${inc.blast.counts.total} connected item(s)${inc.blast.connectedDeployments?.length ? ': ' + inc.blast.connectedDeployments.join(', ') : ''}` : null,
    leak: inc.leak?.summary || null, sameBefore: (inc.similar || [])[0] ? `Seen before as ${inc.similar[0].incidentId} (${inc.similar[0].similarity}% similar). What worked: ${inc.similar[0].procedure.slice(0, 3).join('; ') || 'see that incident'}.` : null,
  };
}
const text = (b) => [`${b.headline}`, `What happened: ${b.whatHappened.join(' / ') || 'see the incident'}`, `Why it matters: ${b.whyItMatters}`, b.alreadyDone.length ? `Already done: ${b.alreadyDone.join('; ')}` : '', b.leak ? `Leak: ${b.leak}` : '', b.affected ? `Affected: ${b.affected}` : '', b.sameBefore || '', `What to do now:\n${b.doNow.map((s, i) => `${i + 1}. ${s}`).join('\n')}`].filter(Boolean).join('\n');
module.exports = { briefing, text };
