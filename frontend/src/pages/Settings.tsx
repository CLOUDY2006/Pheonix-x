import { motion } from 'framer-motion';
import { Check, ExternalLink } from 'lucide-react';
import { useState } from 'react';
import { Btn, Chip, Empty, More, PageHead, Panel, Toggle, cx } from '../components/ui';
import { run } from '../components/shared';
import { api } from '../lib/api';
import { useApp, useCan } from '../lib/store';
import type { Any } from '../types';

const LABEL: Record<string, string> = { watch: 'Watch only', balanced: 'Balanced', full: 'Autopilot' };
const PLAIN: Record<string, string> = {
  watch: 'Phoenix X watches, investigates and recommends. You approve every action yourself.',
  balanced: 'It blocks addresses and revokes sessions on its own, including suspicious accounts. Cautious actions wait for you.',
  full: 'Recommended if you want to do almost nothing. It handles everything it is allowed to and undoes its own blocks once things are quiet. It still never deletes data or shuts machines down.',
};

export function Settings() {
  const { s, me, dispatch, reload } = useApp();
  const { admin } = useCan();
  const au = s.autonomy as Any, st = s.settings as Any, mode: string = au?.mode || 'balanced';
  const [kind, setKind] = useState('user'), [val, setVal] = useState(''), [why, setWhy] = useState('');
  const demo = s.mode === 'demo';
  const setMode = async (k: string) => { const r = await run(() => api('/api/autonomy', 'POST', { mode: k })); if (r) dispatch({ t: 'autonomy', d: r }); };
  const set = async (patch: Record<string, unknown>) => { const r = await run(() => api('/api/settings', 'POST', patch)); if (r) dispatch({ t: 'settings', d: { ...st, ...r } }); };
  const prot: Any[] = au?.protected || [];
  const addProt = async () => { if (!val.trim()) return; const r = await run(() => api('/api/protected', 'POST', { kind, value: val.trim(), reason: why.trim() || 'Added in Settings' }), 'Added. Phoenix X will always ask a person first.'); if (r) { setVal(''); setWhy(''); reload(); } };
  return (
    <div>
      <PageHead title="Settings" sub={<>Signed in as <b>{me?.user}</b> ({me?.role}). {!admin && 'Only an admin can change these.'}</>} />

      <Panel className="mb-5">
        <h2>How much should Phoenix X do alone?</h2>
        <p className="mb-4 text-sub">You can change this any time. It takes effect right away and every change is written to the audit log.</p>
        <div role="radiogroup" aria-label="Protection mode" className="grid gap-3 md:grid-cols-3">
          {['watch', 'balanced', 'full'].map((k) => { const on = mode === k; return (
            <button key={k} role="radio" aria-checked={on} disabled={!admin} onClick={() => setMode(k)} className={cx('relative rounded-2xl border p-5 text-left transition-colors disabled:cursor-not-allowed', on ? 'border-calm bg-surface-2' : 'border-line hover:border-[#2a4a3b]')}>
              {on && <motion.span layoutId="modering" className="absolute inset-0 rounded-2xl ring-2 ring-calm" transition={{ type: 'spring', stiffness: 400, damping: 32 }} />}
              <span className="relative flex items-center justify-between"><b className="font-display text-[18px]">{LABEL[k]}</b>{k === 'full' && !on ? <Chip tone="ok">Least effort</Chip> : on ? <Check size={18} className="text-calm" /> : null}</span>
              <span className="relative mt-2 block text-[14px] text-sub">{PLAIN[k]}</span>
            </button>
          ); })}
        </div>
        <div className="mt-4 grid gap-3 text-[14px] text-sub md:grid-cols-2">
          <p className="rounded-xl bg-surface-2 px-4 py-3"><b className="text-text">In every mode</b>, Phoenix X never deletes data, wipes or shuts down machines, or changes security controls. Those are always left to a person.</p>
          <p className="rounded-xl bg-surface-2 px-4 py-3"><b className="text-text">Safety brake:</b> after {au?.budget?.max ?? 25} automatic actions in an hour, it stops and asks you ({au?.budget?.used ?? 0} used so far{au?.budget?.tripped ? ', limit reached' : ''}).</p>
        </div>
      </Panel>

      <div className="mb-5 grid gap-5 lg:grid-cols-2">
        <Panel>
          <h2 className="mb-1">Always ask a person first</h2>
          <p className="mb-3 text-sub">Accounts, addresses, computers or files that Phoenix X must never change on its own.</p>
          {prot.length ? prot.map((p) => <div key={p.id} className="flex items-center justify-between gap-3 border-t border-line py-2.5 first:border-0"><div className="min-w-0"><b className="break-all font-mono text-[13px]">{p.value}</b> <Chip>{p.kind}</Chip><div className="text-[12.5px] text-mute">{p.reason}</div></div>{admin && <Btn size="sm" onClick={() => run(() => api(`/api/protected/${p.id}/remove`, 'POST', {}), 'Removed').then(reload)}>Remove</Btn>}</div>) : <p className="text-[14px] text-mute">Nothing added yet. Private network addresses are always protected.</p>}
          {admin && <div className="mt-4 flex flex-wrap gap-2"><select aria-label="Kind" className="field" value={kind} onChange={(e) => setKind(e.target.value)}>{['user', 'ip', 'host', 'resource'].map((k) => <option key={k}>{k}</option>)}</select><input aria-label="Value" className="field min-w-[130px] flex-1" placeholder="alice.chen" value={val} onChange={(e) => setVal(e.target.value)} /><input aria-label="Reason" className="field min-w-[130px] flex-1" placeholder="Reason (optional)" value={why} onChange={(e) => setWhy(e.target.value)} /><Btn v="primary" onClick={addProt}>Add</Btn></div>}
        </Panel>
        <Panel>
          <h2 className="mb-1">Alerts, chat and connections</h2>
          <p className="mb-3 text-sub">These tools have their own pages.</p>
          {[['Chat and alerts', 'Telegram, Slack, Discord and email', '/classic/#/channels'], ['Connect a platform', 'Keys, log shippers and read-only collectors', '/classic/#/connect'], ['Users, keys and backups', 'Team accounts, two-factor, key rotation', '/classic/#/settings']].map(([t, h, u]) => (
            <a key={t} href={u} className="flex items-center justify-between gap-3 border-t border-line py-3 first:border-0 hover:text-calm"><span><b className="block font-semibold">{t}</b><span className="text-[13.5px] text-mute">{h}</span></span><ExternalLink size={16} className="shrink-0 text-mute" /></a>
          ))}
          <div className="mt-3 flex flex-wrap gap-2"><Chip tone={demo ? 'info' : 'ok'} dot>{demo ? 'Demo mode' : 'Production mode'}</Chip><Chip tone={st.connectorDryRun ? 'warn' : 'ok'}>{st.connectorDryRun ? 'Connectors in dry-run' : 'Connectors live'}</Chip></div>
        </Panel>
      </div>

      <More title="Connected services and demo tools" hint="For setup and presentations">
        <h3 className="mb-1 font-semibold">Services</h3>
        {Object.entries(s.integrations).map(([k, v]) => <div key={k} className="flex items-center justify-between gap-3 py-1.5"><span>{k}</span><Chip tone={/^configured|^connected|^enabled/.test(String(v)) ? 'ok' : 'neutral'}>{String(v)}</Chip></div>)}
        {!Object.keys(s.integrations).length && <Empty>Nothing to show</Empty>}
        <h3 className="mb-1 mt-5 font-semibold">Approvals</h3>
        <div className="flex items-center justify-between gap-4 py-2"><div><b className="font-semibold">Auto-deny after (minutes)</b><div className="text-[13.5px] text-mute">Unanswered approvals are declined after this long. 0 means never.</div></div><input type="number" min={0} aria-label="Minutes" className="field w-[90px]" disabled={!admin} defaultValue={st.approvalTimeoutMin ?? 0} onBlur={(e) => set({ approvalTimeoutMin: Math.max(0, Number(e.target.value) || 0) })} /></div>
        {demo && <>
          <h3 className="mb-1 mt-5 font-semibold">Demo tools</h3>
          <div className="flex items-center justify-between gap-4 py-3"><div><b className="font-semibold">Background traffic</b><div className="text-[13.5px] text-mute">Creates realistic everyday events.</div></div><Toggle label="Background traffic" checked={!!st.generator} disabled={!admin} onChange={(v) => set({ generator: v })} /></div>
          <div className="py-3"><div className="flex justify-between"><b className="font-semibold">Demo speed</b><span className="text-mute">{st.paceMs} ms between steps</span></div><input type="range" aria-label="Pause between steps" min={0} max={3000} step={100} value={st.paceMs ?? 0} disabled={!admin} onChange={(e) => dispatch({ t: 'settings', d: { ...st, paceMs: +e.target.value } })} onMouseUp={(e) => set({ paceMs: +(e.target as HTMLInputElement).value })} onKeyUp={(e) => set({ paceMs: +(e.target as HTMLInputElement).value })} onTouchEnd={(e) => set({ paceMs: +(e.target as HTMLInputElement).value })} className="mt-2 w-full accent-[#ff7a45]" /><div className="text-[13px] text-mute">Slide right to slow the demo down while you explain it.</div></div>
          <Btn v="danger" disabled={!admin} onClick={() => confirm('Reset the simulated company, incidents and events?') && run(() => api('/api/reset', 'POST', {}), 'Simulation reset')}>Reset the simulation</Btn>
        </>}
      </More>
    </div>
  );
}
