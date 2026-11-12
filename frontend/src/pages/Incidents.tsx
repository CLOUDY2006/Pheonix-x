import { ArrowLeft } from 'lucide-react';
import { useEffect, useState } from 'react';
import { AttackGraph, GraphLegend } from '../components/AttackGraph';
import { StageTrack, StepList } from '../components/StageTrack';
import { ActionTable, AuditTable, Decision, IncTable, IntelTable, NodePanel, RecoveryBlock, ScenarioList, Timeline, run } from '../components/shared';
import { Bar, Btn, Chip, Empty, More, Note, OriginChip, PageHead, Panel, SevChip, StateChip, Table, Tabs, cx } from '../components/ui';
import { api, download } from '../lib/api';
import { DISP, SEV, STATE_TXT, SRC, evMeta, evText, fmtDT, fmtT, nice, plain } from '../lib/format';
import { useApp, useCan, useIncident } from '../lib/store';
import type { Any } from '../types';
import { motion } from 'framer-motion';

type Tab = 'overview' | 'story' | 'response' | 'recovery' | 'records';

export function Incidents({ arg }: { arg?: string }) {
  useEffect(() => { if (!arg) location.replace('#/activity'); }, [arg]);
  return arg ? <Detail id={arg} /> : <Empty>Loading</Empty>;
}

function Detail({ id }: { id: string }) {
  const { d: i, refresh } = useIncident(id);
  const { act } = useCan();
  const [tab, setTab] = useState<Tab>('overview');
  const [analyst, setAnalyst] = useState('');
  const [sel, setSel] = useState<string | null>(null);
  const [note, setNote] = useState('');
  if (!i) return <Empty>Loading {id}</Empty>;
  const inv = i.investigation, pend = i.containment.filter((a: Any) => a.status === 'pending_approval');
  const statuses = [...new Set(['Open', 'In Progress', 'Escalated', 'False Positive', 'Resolved', 'Closed', i.status])];
  const g = inv?.graph?.nodes ? inv.graph : null;
  return (
    <div>
      <a href="#/activity" className="mb-3 inline-flex items-center gap-1.5 text-[14px] text-sub hover:text-text"><ArrowLeft size={15} />Back to activity</a>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex flex-wrap gap-2"><SevChip s={i.severity} /><StateChip s={i.state} /><OriginChip o={i.origin} />{i.degraded && <Chip tone="warn">A helper had a problem</Chip>}</div>
          <h1>{i.title}</h1>
          <p className="mt-1 text-sub">{i.id}. Detected {fmtDT(i.createdAt)}{i.ticket && <> . Ticket {i.ticket.id} <Chip tone={i.ticket.confirmed ? 'ok' : 'neutral'}>{i.ticket.confirmed ? 'Confirmed by Jira' : 'Simulated'}</Chip></>}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="Status" className="field" disabled={!act} value={i.status} onChange={(e) => run(() => api(`/api/incidents/${id}/status`, 'POST', { status: e.target.value }), 'Status updated').then(refresh)}>{statuses.map((x) => <option key={x as string}>{x as string}</option>)}</select>
          <input aria-label="Assign to analyst" className="field w-[130px]" placeholder="Assign to" disabled={!act} defaultValue={i.analyst || ''} onChange={(e) => setAnalyst(e.target.value)} />
          <Btn size="sm" disabled={!act} onClick={() => analyst.trim() && run(() => api(`/api/incidents/${id}/assign`, 'POST', { analyst: analyst.trim() }), 'Assigned').then(refresh)}>Assign</Btn>
        </div>
      </div>
      <Panel><StageTrack workflow={i.workflow} /><More title="Show all 12 steps"><StepList workflow={i.workflow} /></More></Panel>
      <div className="mt-6"><Tabs<Tab> value={tab} onChange={setTab} tabs={[['overview', 'Summary'], ['story', 'What happened'], ['response', 'What we did'], ['recovery', 'Recovery'], ['records', 'Notes and report']]} /></div>

      {tab === 'overview' && (
        <div className="space-y-5">
          {pend.length > 0 && <div className="rounded-2xl border border-[#5a4417] bg-[#0d1a12] px-5 pt-1">{pend.map((a: Any, k: number) => <Decision key={a.id} first={k === 0} a={{ incidentId: i.id, action: a }} />)}</div>}
          <div className="grid gap-5 lg:grid-cols-2">
            <Panel>
              <h2 className="mb-2">What happened</h2>
              <p>Phoenix X linked <b>{i.alerts.length}</b> warning sign{i.alerts.length === 1 ? '' : 's'} into one incident: {[...new Set(i.alerts.map((a: Any) => nice(a.category)))].join(', ')}.</p>
              <p className="mt-2 text-[14px] text-sub">{inv?.summary || 'Investigation in progress.'}</p>
              {inv?.aiNarrative && <Note><b>AI summary.</b> {inv.aiNarrative.text}<div className="text-mute">Written by {inv.aiNarrative.model} on top of the facts. It is not evidence.</div></Note>}
              <dl className="mt-3 grid grid-cols-[120px_1fr] gap-x-4 gap-y-2 text-[14px]">
                <dt className="text-mute">How sure we are</dt><dd><b>{inv?.confidence || 'Not yet known'}</b> <span className="text-mute">{inv?.confidenceReason}</span></dd>
                <dt className="text-mute">Likely way in</dt><dd>{inv?.entryPoint?.description || 'Not yet known'}<div className="text-[13px] text-mute">{inv?.entryPoint?.note}</div></dd>
                <dt className="text-mute">Outcome</dt><dd>{i.resolution || DISP[i.disposition] || nice(i.disposition) || 'Still open'}</dd>
              </dl>
            </Panel>
            <Panel>
              <h2 className="mb-2">How serious is it?</h2>
              <div className="flex items-baseline justify-between"><b className="text-[24px]">{SEV[i.severity] || i.severity}</b><span className="text-sub">Risk {i.riskScore} out of 100. Priority {i.priority}.</span></div>
              <div className="relative my-3 h-2.5 rounded-full" style={{ background: 'linear-gradient(90deg,#2ee6a6 0 40%,#ffc15a 40% 70%,#ff6b6b 70%)' }}><motion.i className="absolute -top-1 h-[18px] w-1 rounded bg-ink ring-2 ring-white" initial={{ left: '0%' }} animate={{ left: `${Math.min(98, Math.max(1, i.riskScore))}%` }} transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }} /></div>
              <div className="flex justify-between text-[12.5px] text-mute"><span>Low</span><span>High</span></div>
              <h3 className="mb-2 mt-5 font-semibold">Affected</h3>
              <div className="flex flex-wrap gap-2">{(inv?.affectedAssets || []).map((a: Any) => <Chip key={a.id}>{a.id}{a.status ? ': ' + a.status : ''}</Chip>)}{!inv?.affectedAssets?.length && <span className="text-sub">Still being worked out</span>}</div>
            </Panel>
          </div>
          <div className="grid gap-5 lg:grid-cols-2">
            <Panel><h2 className="mb-1">Confirmed by evidence</h2>{(inv?.confirmedFindings || []).map((f: Any, k: number) => <Note key={k} tone="ok">{f.statement}</Note>)}{!inv?.confirmedFindings?.length && <p className="text-sub">Nothing confirmed yet</p>}</Panel>
            <Panel><h2 className="mb-1">Still to be confirmed</h2>{(inv?.hypotheses || []).map((h: Any, k: number) => <Note key={k} tone="warn">{h.statement}<div className="text-mute">How to check: {h.toConfirm}</div></Note>)}{!inv?.hypotheses?.length && <p className="text-sub">No open questions</p>}</Panel>
          </div>
          <More title="Why Phoenix X flagged this" hint="Reasons, scoring and playbooks">
            <Table head={['What happened', 'Why it was flagged', 'Sure', 'Suggested']}>{i.alerts.map((a: Any) => <tr key={a.id}><td className="td">{a.explain?.whatHappened}<div className="text-[12.5px] text-mute">{a.rule}, risk {a.riskScore}</div></td><td className="td">{a.explain?.whyFlagged}</td><td className="td">{Math.round((a.explain?.confidence || 0) * 100)}%</td><td className="td">{a.explain?.recommended}</td></tr>)}</Table>
            {i.priorityBreakdown && <><h3 className="mb-2 mt-4 font-semibold">How the priority was calculated</h3>{i.priorityBreakdown.factors.map((f: Any) => <div key={f.name} className="my-2"><div className="mb-1 flex justify-between text-[13.5px]"><span>{f.name}</span><b>{f.value}</b></div><Bar pct={f.value} /></div>)}</>}
            <h3 className="mb-2 mt-4 font-semibold">Known attack techniques (MITRE ATT&CK)</h3>
            {(inv?.techniques || []).map((x: Any) => <div key={x.id} className="my-1.5"><Chip tone={x.status === 'evidence-supported' ? 'ok' : 'warn'}>{x.id}</Chip> <b className="font-semibold">{x.name}</b> <span className="text-mute">{x.status === 'evidence-supported' ? 'seen directly' : 'possible, not proven'}</span></div>)}
            <h3 className="mb-1 mt-4 font-semibold">Matching response playbooks</h3>{i.playbooks.map((p: Any) => <Note key={p.id}><b>{p.title}</b><div className="text-mute">{p.excerpt}</div></Note>)}
          </More>
          {i.emailAnalysis && <More title="The reported email" hint="Checked safely, links never opened"><Note>{i.emailAnalysis.note}</Note><dl className="grid grid-cols-[120px_1fr] gap-2 text-[14px]"><dt className="text-mute">Links</dt><dd className="break-all font-mono text-[12.5px]">{i.emailAnalysis.urls.join(', ')}</dd><dt className="text-mute">Warning signs</dt><dd>{i.emailAnalysis.flags.map((f: string) => <div key={f}>{f}</div>)}</dd><dt className="text-mute">Sent to</dt><dd>{i.emailAnalysis.recipients.join(', ')}</dd><dt className="text-mute">Clicked</dt><dd className="font-semibold text-danger">{i.emailAnalysis.clickers.join(', ') || 'No one yet'}</dd></dl></More>}
        </div>
      )}

      {tab === 'story' && (
        <div className="space-y-5">
          {g ? <div className="grid gap-5 lg:grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)]"><div><AttackGraph g={g} sel={sel} onSelect={setSel} /><GraphLegend /></div><NodePanel g={g} sel={sel} evidence={i.evidence?.items || []} /></div> : <Panel><Empty>The map appears once the investigation has results.</Empty></Panel>}
          <Panel><h2 className="mb-4">Timeline</h2><Timeline items={inv?.timeline || []} /></Panel>
          <More title="Saved evidence" hint={`${i.evidence.count} events, locked in at ${fmtDT(i.evidence.preservedAt)}`}>
            <Note>Fingerprint (SHA-256) <span className="break-all font-mono text-[12.5px]">{i.evidence.sha256}</span></Note>
            <Table head={['Time', 'Event', 'Type']}>{i.evidence.items.map((e: Any) => <tr key={e.id}><td className="td font-mono text-[12.5px]">{fmtT(e.ts)}</td><td className="td"><b className="font-semibold">{evText(e)}</b> <span className="text-mute">{evMeta(e)}</span></td><td className="td"><OriginChip o={e.origin} /></td></tr>)}</Table>
          </More>
        </div>
      )}

      {tab === 'response' && (
        <div className="space-y-5">
          <Panel><h2 className="mb-2">Containment plan</h2><Note>{i.plan?.note || 'The plan appears after the investigation.'}</Note><ActionTable i={i} /></Panel>
          <div className="grid gap-5 lg:grid-cols-2">
            <Panel><h2>Left for humans</h2><p className="mb-1 text-sub">Phoenix X will never do these itself, even if asked.</p>{(i.plan?.manualOnly || []).map((m: Any) => <Note key={m.description} tone="bad"><b>{m.description}</b><div className="text-mute">{m.why}</div></Note>)}{!i.plan?.manualOnly?.length && <p className="text-sub">Nothing</p>}</Panel>
            <Panel><h2 className="mb-1">Approval history</h2>{i.approvals.map((a: Any, k: number) => <Note key={k} tone={a.decision === 'approved' ? 'ok' : 'bad'}><b>{a.decision === 'approved' ? 'Approved' : 'Declined'}: {a.description}</b><div className="text-mute">{a.by}, {fmtDT(a.ts)} {a.comment}</div></Note>)}{!i.approvals.length && <p className="text-sub">No approvals were needed</p>}</Panel>
          </div>
          <Panel><h2 className="mb-1">Threat lookups</h2><p className="mb-2 text-sub">{i.intel?.summary}</p><IntelTable list={i.intel?.indicators || []} /></Panel>
        </div>
      )}

      {tab === 'recovery' && <RecoveryBlock i={i} />}

      {tab === 'records' && (
        <div className="space-y-5">
          <Panel>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3"><h2>Final report</h2><div className="flex gap-2"><Btn size="sm" disabled={!i.report} onClick={() => run(() => download(`/api/incidents/${id}/report.md`, `${id}-report.md`))}>Download report</Btn><Btn size="sm" onClick={() => run(() => download(`/api/incidents/${id}/report.json`, `${id}-evidence-bundle.json`))}>Download evidence bundle</Btn></div></div>
            {i.report ? <pre className="max-h-[480px] overflow-auto whitespace-pre-wrap rounded-xl bg-[#0c1f17] p-4 font-mono text-[13px] leading-relaxed">{i.report}</pre> : <Empty>The report is written at the end of the response.</Empty>}
          </Panel>
          <Panel>
            <h2 className="mb-2">Investigation notes</h2>
            {i.notes.map((n: Any, k: number) => <Note key={k}><b>{n.by}</b>, {fmtDT(n.ts)}<br />{n.text}</Note>)}{!i.notes.length && <p className="text-sub">No notes yet</p>}
            <textarea aria-label="New note" className="field mt-3 min-h-[80px] w-full" placeholder="Write a note for the team" value={note} disabled={!act} onChange={(e) => setNote(e.target.value)} />
            <Btn v="primary" size="sm" className="mt-2" disabled={!act || !note.trim()} onClick={() => run(() => api(`/api/incidents/${id}/notes`, 'POST', { text: note.trim() }), 'Note added').then(() => { setNote(''); refresh(); })}>Add note</Btn>
          </Panel>
          <More title="Full audit history" hint={`${i.audit.length} entries`}><AuditTable rows={i.audit} /></More>
        </div>
      )}
    </div>
  );
}
