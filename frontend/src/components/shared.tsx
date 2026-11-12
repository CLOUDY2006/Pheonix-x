import { motion, AnimatePresence } from 'framer-motion';
import { Database, Eye, Gauge, KeyRound, Lock, Mail, Cloud, Plane, Play, X, type LucideIcon } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import type { Any, Approval, EventT, IncidentSummary, Scenario } from '../types';
import { api } from '../lib/api';
import { evMeta, evText, fmtDT, fmtT, ifNo, plain, SRC, SUSP } from '../lib/format';
import { go, useApp, useCan, useIncident } from '../lib/store';
import { toast } from '../lib/toast';
import { Bar, Btn, Chip, Empty, Mono, Note, OriginChip, Panel, SevChip, StateChip, Table, TierChip, cx } from './ui';
import { KIND_ICON } from './AttackGraph';

export async function run<T>(fn: () => Promise<T>, ok?: string): Promise<T | undefined> {
  try { const r = await fn(); if (ok) toast(ok, 'ok'); return r; } catch (e) { toast((e as Error).message, 'bad'); }
}

export function useLaunch() {
  const { s } = useApp();
  return (id: string) => { if (id === 'signature') go('#/command'); return run(() => api(`/api/scenarios/${id}/launch`, 'POST', { autopilot: !!s.settings.autopilot }), 'Demo started. Watch the four stages.'); };
}

export function WhyLink({ incidentId }: { incidentId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="link text-[14px] font-medium" onClick={() => setOpen(true)}>Why?</button>
      <AnimatePresence>{open && <WhyDrawer incidentId={incidentId} onClose={() => setOpen(false)} />}</AnimatePresence>
    </>
  );
}

function WhyDrawer({ incidentId, onClose }: { incidentId: string; onClose: () => void }) {
  const { d } = useIncident(incidentId);
  const inv = d?.investigation;
  return (
    <motion.div className="fixed inset-0 z-50 flex justify-end bg-black/60" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}>
      <motion.aside role="dialog" aria-label="Why Phoenix X suggests this" onClick={(e) => e.stopPropagation()} className="h-full w-full max-w-[480px] overflow-y-auto bg-surface p-6 shadow-2xl"
        initial={{ x: 60, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 60, opacity: 0 }} transition={{ type: 'spring', stiffness: 320, damping: 32 }}>
        <div className="mb-4 flex items-start justify-between gap-4"><div><div className="text-[13px] text-mute">The evidence</div><h2 className="text-[20px]">{d?.title || incidentId}</h2></div><button aria-label="Close" onClick={onClose} className="rounded-lg p-2 text-mute hover:bg-[#0c1f17]"><X size={18} /></button></div>
        {!d ? <Empty>Loading</Empty> : <>
          <p className="text-[15px]">{inv?.summary}</p>
          <div className="mt-3 flex flex-wrap gap-2"><SevChip s={d.severity} /><Chip>How sure: {inv?.confidence || 'not yet known'}</Chip></div>
          <h3 className="mb-1 mt-5 font-semibold">Why it was flagged</h3>
          {d.alerts.map((al: Any) => <Note key={al.id}><b>{al.explain?.whatHappened}</b><div className="text-sub">{al.explain?.whyFlagged}</div></Note>)}
          <h3 className="mb-1 mt-5 font-semibold">What we saw</h3>
          <ul className="space-y-1.5 text-[14px]">{d.evidence.items.slice(0, 8).map((e: Any) => <li key={e.id} className="flex gap-3"><Mono className="text-mute">{fmtT(e.ts)}</Mono><span>{evText(e)} <span className="text-mute">{evMeta(e)}</span></span></li>)}</ul>
          {d.evidence.items.length > 8 && <p className="mt-2 text-[13px] text-mute">and {d.evidence.items.length - 8} more events</p>}
          <Btn v="primary" className="mt-6 w-full" onClick={() => { onClose(); go('#/incidents/' + incidentId); }}>Open the full incident</Btn>
        </>}
      </motion.aside>
    </motion.div>
  );
}

export function Decision({ a, first }: { a: Approval; first?: boolean }) {
  const { dispatch } = useApp();
  const { admin } = useCan();
  const { d } = useIncident(a.incidentId);
  const happened = d?.alerts?.[0]?.explain?.whatHappened || d?.title || 'Something suspicious was found';
  const decide = async (what: 'approve' | 'reject') => {
    await run(() => api(`/api/actions/${a.action.id}/${what}`, 'POST', { comment: 'via console' }), what === 'approve' ? 'Done. Phoenix X is carrying it out.' : 'Okay, nothing will change.');
    dispatch({ t: 'dropApproval', d: a.action.id });
  };
  const Block = ({ k, children }: { k: string; children: ReactNode }) => <div><div className="mb-0.5 text-[12.5px] font-medium text-mute">{k}</div><div className="text-[14.5px] leading-snug">{children}</div></div>;
  return (
    <motion.div layout exit={{ opacity: 0, height: 0, marginTop: 0 }} className={cx('rounded-3xl border border-[#5a4417] bg-surface p-6 shadow-[0_18px_40px_-22px_rgba(224,147,15,.55)]', !first && 'mt-4')}>
      <div className="grid gap-5 md:grid-cols-3">
        <Block k="What happened">{happened}</Block>
        <Block k="Phoenix X wants to"><b className="font-semibold">{a.action.description}</b></Block>
        <Block k="If you say no">{a.action.ifNo || ifNo(a.action.type)}</Block>
      </div>
      <div className="mt-5 flex flex-wrap items-center gap-3">
        <Btn v="ok" size="lg" onClick={() => decide('approve')} disabled={!admin}>Approve</Btn>
        <Btn v="outline" size="lg" onClick={() => decide('reject')} disabled={!admin}>No, don’t</Btn>
        <span className="ml-1"><WhyLink incidentId={a.incidentId} /></span>
      </div>
    </motion.div>
  );
}

export function useApproveAll() {
  const { s, dispatch } = useApp();
  return async () => {
    const ids = s.approvals.map((a) => a.action.id);
    await Promise.all(ids.map((id) => api(`/api/actions/${id}/approve`, 'POST', { comment: 'Approve all' }).catch(() => null)));
    ids.forEach((id) => dispatch({ t: 'dropApproval', d: id }));
    toast('Done. Phoenix X is carrying them out.', 'ok');
  };
}

export function DecisionPanel({ title }: { title?: string }) {
  const { s } = useApp();
  const { admin } = useCan();
  const approveAll = useApproveAll();
  return (
    <AnimatePresence initial={false}>
      {s.approvals.length > 0 && (
        <motion.div id="decisions" initial={{ opacity: 0, height: 0, y: -10 }} animate={{ opacity: 1, height: 'auto', y: 0 }} exit={{ opacity: 0, height: 0 }} className="mb-5 overflow-hidden">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">{title ? <h2>{title}</h2> : <span />}{admin && s.approvals.length > 1 && <Btn size="sm" v="ok" onClick={approveAll}>Approve all {s.approvals.length}</Btn>}</div>
          <AnimatePresence initial={false}>{s.approvals.map((a, i) => <Decision key={a.action.id} a={a} first={i === 0} />)}</AnimatePresence>
          {!admin && <p className="mt-3 rounded-lg bg-warn-soft px-3 py-2 text-[14px] text-warn">Only an admin can decide. Ask an admin, or switch Phoenix X to Autopilot in Settings.</p>}
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export function EventRow({ e, isNew }: { e: EventT; isNew?: boolean }) {
  const sus = e.origin === 'scenario' && SUSP.has(e.type);
  return (
    <motion.li layout="position" initial={isNew ? { opacity: 0, y: -10, backgroundColor: 'rgba(126,161,255,.18)' } : false} animate={{ opacity: 1, y: 0, backgroundColor: sus ? '#fdecec' : 'rgba(255,255,255,0)' }} transition={{ duration: 0.5 }}
      className={cx('grid grid-cols-[62px_74px_minmax(0,1fr)] items-baseline gap-3 border-b border-line px-5 py-2 text-[14px] sm:grid-cols-[62px_90px_minmax(0,1fr)]', sus && 'shadow-[inset_3px_0_#ff6b6b]')}>
      <Mono className="text-mute">{fmtT(e.ts)}</Mono><span className="text-mute">{SRC[e.source] || e.source}</span>
      <span><b className="font-semibold" title={e.type}>{evText(e)}</b> <span className="text-mute">{evMeta(e)}</span>{e.origin !== 'generated' && <> <OriginChip o={e.origin} /></>}</span>
    </motion.li>
  );
}

export function EventFeed({ events, max = 40, height = 340 }: { events: EventT[]; max?: number; height?: number }) {
  const list = events.slice(-max).reverse();
  return list.length ? <ul className="overflow-y-auto" style={{ maxHeight: height }}>{list.map((e, i) => <EventRow key={e.id} e={e} isNew={i < 2} />)}</ul> : <Empty>Waiting for events</Empty>;
}

export function IncTable({ list }: { list: IncidentSummary[] }) {
  if (!list.length) return <Empty>No incidents yet. Run the attack demo to see Phoenix X respond.</Empty>;
  return (
    <Table head={['Incident', 'How serious', 'Where it stands', 'Detected']}>
      {list.map((i) => (
        <tr key={i.id} tabIndex={0} onClick={() => go('#/incidents/' + i.id)} onKeyDown={(e) => e.key === 'Enter' && go('#/incidents/' + i.id)} className="cursor-pointer transition-colors hover:bg-[#0c1f17]">
          <td className="td"><div className="font-semibold">{i.title}</div><div className="text-[13px] text-mute">{i.id}</div></td>
          <td className="td"><SevChip s={i.severity} /></td><td className="td"><StateChip s={i.state} /></td><td className="td text-mute">{fmtT(i.createdAt)}</td>
        </tr>
      ))}
    </Table>
  );
}

const SC_ICON: Record<string, LucideIcon> = { 'credential-compromise': KeyRound, ransomware: Lock, 'insider-threat': Eye, phishing: Mail, 'cloud-compromise': Cloud, 'benign-travel': Plane, 'leaked-api-key': KeyRound, 'rate-limit-abuse': Gauge, 'database-compromise': Database };
export function ScenarioList({ list }: { list: Scenario[] }) {
  const launch = useLaunch();
  const { act } = useCan();
  return (
    <ul>{list.map((x) => (
      <li key={x.id} className="flex items-center gap-4 border-t border-line py-3 first:border-0">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-[#0c1f17] text-ink-3">{(() => { const I = SC_ICON[x.id] || Play; return <I size={18} />; })()}</span>
        <div className="min-w-0 flex-1"><div className="font-semibold">{x.name}</div><p className="text-[13.5px] text-sub">{x.blurb}</p></div>
        <Btn size="sm" onClick={() => launch(x.id)} disabled={!act}>Run</Btn>
      </li>
    ))}</ul>
  );
}

export const statusText = (st: string) => ({ executed: ['Done', 'text-calm'], pending_approval: ['Waiting for you', 'text-warn'], rolled_back: ['Undone', 'text-sub'], denied: ['Declined', 'text-danger'], blocked: ['Blocked', 'text-danger'], failed: ['Failed', 'text-danger'], approved: ['Approved', 'text-calm'], planned: ['Planned', 'text-sub'] } as Record<string, [string, string]>)[st] || [st, 'text-sub'];

export function ActionTable({ i }: { i: Any }) {
  const { dispatch } = useApp();
  const { admin } = useCan();
  const decide = async (id: string, what: string) => { await run(() => api(`/api/actions/${id}/${what}`, 'POST', { comment: 'via console' }), what === 'approve' ? 'Approved. Phoenix X is carrying it out.' : 'Declined.'); dispatch({ t: 'dropApproval', d: id }); };
  if (!i.containment.length) return <Empty>No actions were needed. Phoenix X is only keeping watch.</Empty>;
  return (
    <Table head={['Action', 'Type', 'Status', '']}>
      {i.containment.map((a: Any) => { const [t, c] = statusText(a.status); return (
        <tr key={a.id}><td className="td"><div>{a.description}</div><div className="text-[13px] text-mute">{plain(a.reason)}</div></td><td className="td"><TierChip t={a.tier} /></td>
          <td className="td"><b className={c}>{t}</b>{a.result && <div className="text-[13px] text-calm">{a.result.detail}{a.result.providerConfirmed ? ' (confirmed)' : ''}</div>}</td>
          <td className="td text-right">{a.status === 'pending_approval' && <span className="inline-flex gap-2"><Btn size="sm" v="ok" disabled={!admin} onClick={() => decide(a.id, 'approve')}>Approve</Btn><Btn size="sm" v="danger" disabled={!admin} onClick={() => decide(a.id, 'reject')}>Decline</Btn></span>}</td></tr>
      ); })}
    </Table>
  );
}

export function RecoveryBlock({ i }: { i: Any }) {
  const { act } = useCan();
  const r = i.recovery, done = r.tasks.filter((t: Any) => t.status === 'done').length;
  const humanLeft = r.tasks.some((t: Any) => t.status === 'pending' && t.owner === 'human');
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <Panel><h2 className="mb-3">Can we restore?</h2>
          {r.readiness.map((x: Any) => <Note key={x.host} tone={x.status === 'ready' ? 'ok' : 'bad'}><b className="font-mono text-[13px]">{x.host}</b> <Chip tone={x.status === 'ready' ? 'ok' : 'bad'}>{x.status === 'ready' ? 'Ready' : x.status}</Chip>{x.impacted && <> <Chip tone="bad">Affected</Chip></>}<div className="text-sub">{x.note}</div></Note>)}
          {!r.readiness.length && <p className="text-sub">Nothing needs to be restored.</p>}
        </Panel>
        <Panel>
          <div className="mb-2 flex items-center justify-between"><h2>Recovery tasks</h2><span className="text-sub">{done} of {r.tasks.length} done</span></div>
          <Bar pct={r.tasks.length ? (done / r.tasks.length) * 100 : 0} tone="calm" />
          <ul className="mt-3 space-y-3">{r.tasks.map((t: Any) => (
            <li key={t.id} className="rounded-2xl bg-surface-2 p-3.5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0"><span className={t.status === 'done' ? 'font-semibold text-calm' : t.status === 'failed' ? 'font-semibold text-danger' : t.status === 'skipped' ? 'text-mute' : 'text-warn'}>{t.status === 'done' ? 'Done' : t.status === 'failed' ? 'Failed' : t.status === 'skipped' ? 'Skipped' : t.owner === 'human' ? 'Needs you' : 'In progress'}</span> {t.title} {t.owner === 'human' ? <Chip>You</Chip> : <Chip tone="ok">Automatic</Chip>} {t.optional && <Chip>Optional</Chip>}{t.error && <div className="text-[13px] text-danger">{t.error}</div>}</div>
                {t.status === 'pending' && t.owner === 'human' && <div className="flex shrink-0 gap-1.5">{t.checkable && <Btn size="sm" disabled={!act} onClick={() => run(() => api(`/api/incidents/${i.id}/tasks/${t.id}/check`, 'POST', {}), 'Checked')}>Check it</Btn>}{t.optional && <Btn size="sm" disabled={!act} onClick={() => run(() => api(`/api/incidents/${i.id}/tasks/${t.id}/skip`, 'POST', {}))}>Skip</Btn>}<Btn size="sm" v="primary" disabled={!act} onClick={() => run(() => api(`/api/incidents/${i.id}/tasks/${t.id}/complete`, 'POST', {}))}>Done</Btn></div>}
              </div>
              {t.status === 'pending' && t.owner === 'human' && ((t.how || []).length > 0 || (t.links || []).length > 0) && <div className="mt-2 text-[13.5px] text-sub">{(t.how || []).map((h: string, n: number) => <div key={n}>{n + 1}. {h}</div>)}{(t.links || []).map((l: Any) => <a key={l.url} className="link mr-3 inline-block" href={l.url} target="_blank" rel="noreferrer">{l.label}</a>)}</div>}
            </li>
          ))}</ul>
          {humanLeft && <Btn v="primary" size="sm" className="mt-3" disabled={!act} onClick={() => run(() => api(`/api/incidents/${i.id}/tasks/complete-all`, 'POST', {}), 'Tasks completed')}>Complete all ready tasks</Btn>}
        </Panel>
      </div>
      <Panel>
        <div className="flex items-center justify-between"><h2>Did the fix work?</h2>{i.verification && <Chip tone={i.verification.passed ? 'ok' : 'warn'}>{i.verification.passed ? 'All checks passed' : i.verification.failed + ' failed'}</Chip>}</div>
        {i.verification ? <>
          <ul className="mt-3 space-y-1.5">{i.verification.checks.map((c: Any) => <li key={c.name}><b className={c.pass ? 'text-calm' : 'text-danger'}>{c.pass ? 'Passed' : 'Failed'}</b> {c.name} <span className="text-mute">{c.detail}</span></li>)}</ul>
          <Btn size="sm" className="mt-3" disabled={!act} onClick={() => run(() => api(`/api/incidents/${i.id}/verify`, 'POST', {}), 'Checks re-run')}>Check again</Btn>
        </> : <p className="mt-2 text-sub">Checks run after the recovery tasks are finished.</p>}
      </Panel>
    </div>
  );
}

const VERDICT: Record<string, ['bad' | 'warn' | 'neutral' | 'ok', string]> = { malicious: ['bad', 'Malicious'], suspicious: ['warn', 'Suspicious'], unknown: ['neutral', 'Unknown'], no_detections: ['ok', 'No detections'] };
export function IntelTable({ list }: { list: Any[] }) {
  if (!list.length) return <Empty>Nothing to show</Empty>;
  return (
    <Table head={['Item', 'Verdict', 'Source', 'Notes']}>
      {list.map((x) => { const [tone, label] = VERDICT[x.verdict] || ['neutral', x.verdict]; const ind = String(x.indicator); return (
        <tr key={x.indicator}><td className="td"><div className="text-[12.5px] text-mute">{x.type}</div><Mono className="break-all">{ind.length > 40 ? ind.slice(0, 18) + '…' + ind.slice(-8) : ind}</Mono></td><td className="td"><Chip tone={tone}>{label}</Chip></td><td className="td text-sub">{x.source}{x.live ? ' (live)' : ''}</td><td className="td text-[13.5px] text-sub">{x.detail} {(x.tags || []).map((t: string) => <span key={t} className="mr-1 rounded border border-line bg-[#0c1f17] px-1.5 font-mono text-[12px]">{t}</span>)}</td></tr>
      ); })}
    </Table>
  );
}

export function AuditTable({ rows }: { rows: Any[] }) {
  return (
    <Table head={['#', 'Time', 'Who', 'What', 'Incident', 'Detail']}>
      {rows.map((e) => <tr key={e.seq}><td className="td"><Mono className="text-mute">{e.seq}</Mono></td><td className="td"><Mono className="text-sub">{fmtT(e.ts)}</Mono></td><td className="td font-semibold">{e.actor}</td><td className="td"><Mono>{e.action}</Mono></td><td className="td"><Mono>{e.incidentId || ''}</Mono></td><td className="td max-w-[380px] break-words text-[13px] text-sub">{JSON.stringify(e.detail).slice(0, 180)}</td></tr>)}
    </Table>
  );
}

export function Timeline({ items }: { items: Any[] }) {
  return (
    <ol className="ml-2 border-l-2 border-line pl-5">
      {items.map((t, k) => (
        <motion.li key={k} initial={{ opacity: 0, x: -6 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} className="relative pb-4">
          <span className={cx('absolute -left-[27px] top-1.5 h-3 w-3 rounded-full border-2 bg-surface', t.suspicious ? 'border-danger bg-danger' : 'border-[#2a4a3b]')} />
          <div className="text-[12.5px] text-mute">{t.phase} at {fmtT(t.ts)}{t.source ? ` (${SRC[t.source] || t.source})` : ''}</div><div>{t.summary}</div>
        </motion.li>
      ))}
    </ol>
  );
}

export function AgentLine({ k, name, role, state, current }: { k: string; name: string; role: string; state?: string; current?: string }): ReactNode {
  const working = state === 'working';
  return <div key={k} className="my-2 flex items-center gap-3"><span className={cx('h-2.5 w-2.5 rounded-full', working ? 'animate-pulse bg-ember' : 'bg-[#2a4a3b]')} /><b className="w-[100px] font-semibold">{name}</b><span className="text-[14px] text-sub">{working ? current || 'Working' : role}</span></div>;
}

export function NodePanel({ g, sel, evidence }: { g: Any; sel: string | null; evidence: Any[] }) {
  const n = g?.nodes?.find((x: Any) => x.id === sel);
  if (!n) return <Panel><h2 className="mb-2">Details</h2><Empty>Select any item on the map to see what we know about it.</Empty></Panel>;
  const evs = evidence.filter((e) => n.evidence.includes(e.id));
  const Icon = KIND_ICON[n.kind];
  return (
    <Panel>
      <div className="mb-2 flex items-center gap-2">{Icon && <Icon size={18} className="text-sub" />}<h2 className="break-all">{n.label}</h2></div>
      <div className="flex gap-2"><Chip>{n.kind}</Chip>{n.suspicious && <Chip tone="warn">Suspicious</Chip>}</div>
      {n.summary && <p className="mt-3">{n.summary}</p>}
      {n.intel && <Note>Threat lookup ({n.intel.source}): <b className={n.intel.verdict === 'malicious' ? 'text-danger' : ''}>{n.intel.verdict}</b> {(n.intel.tags || []).map((t: string) => <span key={t} className="mr-1 rounded border border-line bg-surface px-1.5 font-mono text-[12px]">{t}</span>)}</Note>}
      <h3 className="mb-1 mt-4 font-semibold">Evidence ({evs.length})</h3>
      {evs.length ? evs.slice(0, 12).map((e) => <details key={e.id} className="my-1.5 rounded-lg border border-line px-3 py-2"><summary className="cursor-pointer text-[14px]"><span className="text-mute">{fmtT(e.ts)}</span> <b className="font-semibold">{evText(e)}</b> <span className="text-mute">{evMeta(e)}</span></summary><pre className="mt-2 overflow-auto rounded bg-[#0c1f17] p-2 font-mono text-[12px]">{JSON.stringify(e.details, null, 1)}</pre></details>) : <p className="text-sub">This item has no events of its own. Select a connected event to see evidence.</p>}
    </Panel>
  );
}

