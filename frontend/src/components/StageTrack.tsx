import { motion } from 'framer-motion';
import { Check, LifeBuoy, Radar, Search, ShieldHalf, X, type LucideIcon } from 'lucide-react';
import type { Step } from '../types';
import { EASE, cx } from './ui';
import { PHASES, STEP_TXT, phaseState } from '../lib/format';

const ICON: LucideIcon[] = [Radar, Search, ShieldHalf, LifeBuoy];

export function StageTrack({ workflow, idle = false }: { workflow?: Step[]; idle?: boolean }) {
  const wf = workflow || [];
  const states = PHASES.map((p) => (idle ? 'pending' : phaseState(wf, p.keys)));
  return (
    <ol className="grid grid-cols-2 gap-x-3 gap-y-7 md:grid-cols-4">
      {PHASES.map((p, i) => {
        const st = states[i], Icon = ICON[i];
        const run = p.keys.map((k) => wf.find((x) => x.key === k)).find((s) => s && s.status === 'running');
        return (
          <li key={p.name} className="relative">
            {i < 3 && (
              <div className="absolute left-[68px] right-[-4px] top-[27px] hidden h-1 overflow-hidden rounded-full bg-black/[.07] md:block">
                <motion.div className="h-full origin-left rounded-full bg-gradient-to-r from-calm to-[#34d3a0]" initial={false} animate={{ scaleX: st === 'done' ? 1 : st === 'active' ? 0.45 : 0 }} transition={{ duration: 0.9, ease: EASE }} />
              </div>
            )}
            <div className="relative mb-3 h-14 w-14">
              {st === 'active' && <span className="absolute inset-0 animate-ping2 rounded-2xl bg-ember/40" />}
              <motion.div layout className={cx('relative grid h-14 w-14 place-items-center rounded-2xl',
                st === 'done' ? 'bg-calm text-onink shadow-[0_12px_22px_-10px_rgba(18,163,127,.9)]' : st === 'failed' ? 'bg-danger text-onink' : st === 'active' ? 'bg-gradient-to-br from-[#ff7a45] to-[#ff4d5e] text-onink shadow-[0_14px_26px_-10px_rgba(255,90,60,.9)]' : 'bg-surface text-mute shadow-soft ring-1 ring-white/5')}
                animate={{ scale: st === 'active' ? 1.06 : 1 }} transition={{ type: 'spring', stiffness: 300, damping: 18 }}>
                <Icon size={24} />
                {st === 'done' && <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: 'spring', stiffness: 400, damping: 14, delay: 0.1 }} className="absolute -bottom-1.5 -right-1.5 grid h-6 w-6 place-items-center rounded-full bg-surface text-calm shadow ring-1 ring-white/5"><Check size={14} strokeWidth={3.5} /></motion.span>}
                {st === 'failed' && <span className="absolute -bottom-1.5 -right-1.5 grid h-6 w-6 place-items-center rounded-full bg-surface text-danger shadow"><X size={14} strokeWidth={3.5} /></span>}
              </motion.div>
            </div>
            <div className="font-display text-[19px] font-bold leading-tight">{p.name}</div>
            <div className="min-h-[42px] pr-2 text-[13.5px] leading-snug text-sub">{st === 'active' && run ? STEP_TXT[run.key] : p.cap}</div>
            <div className={cx('mt-0.5 text-[13px] font-semibold', st === 'done' ? 'text-calm-dark' : st === 'active' ? 'text-ember-dark' : st === 'failed' ? 'text-danger' : 'text-mute')}>
              {idle ? 'Ready' : { done: 'Done', active: 'In progress', pending: 'Waiting', failed: 'Needs attention' }[st]}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function StepList({ workflow }: { workflow: Step[] }) {
  return (
    <ul className="grid gap-x-8 md:grid-cols-2">
      {workflow.map((s) => (
        <li key={s.key} title={s.note} className="flex items-center gap-3 border-b border-line py-2.5 text-[14px]">
          <span className={cx('h-2.5 w-2.5 shrink-0 rounded-full', s.status === 'done' ? 'bg-calm' : s.status === 'running' ? 'bg-ember' : s.status === 'failed' ? 'bg-danger' : 'bg-[#2a4a3b]')} />
          <span>{STEP_TXT[s.key] || s.label}</span><span className="ml-auto text-[12.5px] text-mute">{s.agent.charAt(0) + s.agent.slice(1).toLowerCase()}</span>
        </li>
      ))}
    </ul>
  );
}
