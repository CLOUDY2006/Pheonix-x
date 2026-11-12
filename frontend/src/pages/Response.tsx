import { useEffect, useState } from 'react';
import { ActionTable, Decision, run } from '../components/shared';
import { Btn, Chip, Empty, More, PageHead, Panel, Table, TierChip, Toggle } from '../components/ui';
import { api } from '../lib/api';
import { plain } from '../lib/format';
import { statusText } from '../components/shared';
import { useAllDetails, useApp, useCan } from '../lib/store';
import type { Any } from '../types';

export function Response() {
  const { s } = useApp();
  const { admin, act: canAct } = useCan();
  const [blocks, setBlocks] = useState<Any[]>([]);
  const loadBlocks = () => api('/api/containments').then((r) => setBlocks(r.containments || [])).catch(() => {});
  const sig = s.incidents.map((i) => i.id + i.actions + i.state).join();
  useEffect(() => { loadBlocks(); }, [sig]);
  const undo = async (id: string, trust: boolean) => { await run(() => api(`/api/actions/${id}/undo`, 'POST', trust ? { trust: true, reason: 'Trusted from Safety rules' } : {}), trust ? 'Unblocked and trusted. Phoenix X will always ask a person first.' : 'Unblocked. Phoenix X will not re-apply it by itself for 24 hours.'); loadBlocks(); };
  const all = useAllDetails();
  const acts = all.flatMap((i) => i.containment.map((a: Any) => ({ ...a, inc: i.id })));
  const [type, setType] = useState('shutdown_host');
  const [target, setTarget] = useState('{"host":"srv-files-01"}');
  const [approve, setApprove] = useState(true);
  const [out, setOut] = useState('');
  const attempt = async () => { let t; try { t = JSON.parse(target); } catch { return run(async () => { throw new Error('The target must be valid JSON.'); }); } const r = await run(() => api('/api/guardian/execute', 'POST', { type, target: t, approve })); if (r) setOut(JSON.stringify(r, null, 2)); };
  return (
    <div>
      <PageHead title="Safety rules" sub="Phoenix X can only take a short list of pre-approved actions, and every one is checked against the safety rules again right before it runs." />
      <div className="mb-5 grid gap-4 md:grid-cols-3">
        {[['automatic', 'Low-risk and reversible, and only in the test environment. For example blocking an address or ending a session.'], ['approval', 'Higher impact, like suspending an account or isolating a computer. An admin must approve first.'], ['restricted', 'Deleting data, shutting down systems or changing security controls. Never done automatically, even if approved.']].map(([t, p]) => <Panel key={t}><TierChip t={t} /><p className="mt-3 text-[14px] text-sub">{p}</p></Panel>)}
      </div>
      <Panel className="mb-5 p-0"><h2 className="px-5 pt-5">Active blocks ({blocks.length})</h2><p className="px-5 text-[14px] text-sub">Things Phoenix X is currently holding back. Undo any of them if it got it wrong.</p>
        {blocks.length ? <Table head={['What', 'Incident', 'Expires', '']}>{blocks.map((b) => <tr key={b.id}><td className="td">{b.description}</td><td className="td text-[13px] text-mute">{b.incidentTitle}</td><td className="td whitespace-nowrap text-[13px] text-mute">{b.expiresAt ? new Date(b.expiresAt).toLocaleString([], { hour12: false }) : 'No expiry'}</td><td className="td text-right"><span className="inline-flex gap-2"><Btn size="sm" disabled={!canAct} onClick={() => undo(b.id, false)}>Unblock</Btn>{admin && <Btn size="sm" onClick={() => undo(b.id, true)}>Unblock and trust</Btn>}</span></td></tr>)}</Table> : <Empty>Nothing is blocked right now</Empty>}
      </Panel>
      <Panel className="mb-5"><h2 className="mb-1">Waiting for approval</h2>{s.approvals.length ? s.approvals.map((a, k) => <Decision key={a.action.id} a={a} first={k === 0} />) : <Empty>Nothing is waiting for a decision</Empty>}</Panel>
      <Panel className="mb-5 p-0"><h2 className="px-5 pt-5">Everything done so far ({acts.length})</h2>
        {acts.length ? <Table head={['Incident', 'Action', 'Type', 'Status']}>{acts.map((a: Any) => { const [t, c] = statusText(a.status); return <tr key={a.id}><td className="td whitespace-nowrap font-mono text-[12.5px]">{a.inc}</td><td className="td">{a.description}<div className="text-[13px] text-mute">{plain(a.reason)}</div></td><td className="td"><TierChip t={a.tier} /></td><td className="td"><b className={c}>{t}</b><div className="text-[13px] text-mute">{a.result?.detail || a.error || ''}{a.approvedBy && <><br />Approved by {a.approvedBy}</>}</div></td></tr>; })}</Table> : <Empty>No actions yet</Empty>}
      </Panel>
      {s.mode === 'demo' && (
      <More title="Test the safety rules" hint="Admin only">
        <p className="mb-3 text-sub">Try a dangerous action. It is refused even when you turn on “approve”.</p>
        <div className="flex flex-wrap items-center gap-3">
          <select aria-label="Action" className="field" value={type} onChange={(e) => setType(e.target.value)}>{['block_ip', 'revoke_sessions', 'disable_account', 'isolate_host', 'shutdown_host', 'delete_data', 'wipe_host', 'modify_security_control', 'rm_rf_everything'].map((t) => <option key={t}>{t}</option>)}</select>
          <input aria-label="Target" className="field min-w-[220px] flex-1 font-mono" value={target} onChange={(e) => setTarget(e.target.value)} />
          <label className="flex items-center gap-2 text-[14px] text-sub"><Toggle label="Approve" checked={approve} onChange={setApprove} />Approve</label>
          <Btn v="primary" disabled={!admin} onClick={attempt}>Try it</Btn>
        </div>
        <pre className="mt-3 min-h-[48px] overflow-auto rounded-xl bg-[#0c1f17] p-3 font-mono text-[12.5px]">{out}</pre>
      </More>
      )}
    </div>
  );
}
