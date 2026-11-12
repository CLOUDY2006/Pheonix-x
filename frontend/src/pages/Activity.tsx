import { motion } from 'framer-motion';
import { ChevronRight } from 'lucide-react';
import { Chip, Empty, PageHead, Panel, SevChip, StateChip, cx } from '../components/ui';
import { buildActivity, fmtDT, isActiveState, plain } from '../lib/format';
import { go, useAllDetails, useApp } from '../lib/store';
import type { Any } from '../types';

function didLine(i: Any): string {
  const done = (i.containment || []).filter((a: Any) => a.status === 'executed');
  if (done.length) return `${done[0].description}${done.length > 1 ? ` and ${done.length - 1} more ${done.length === 2 ? 'action' : 'actions'}` : ''}.`;
  if ((i.containment || []).some((a: Any) => a.status === 'pending_approval')) return 'Waiting for your OK on the next step.';
  return i.state === 'MONITORING' ? 'Low risk. Keeping an eye on it.' : 'Investigating what happened.';
}

export function Activity() {
  const { s } = useApp();
  const all = useAllDetails();
  const lines = buildActivity(all).slice(0, 80);
  const open = s.incidents.filter((i) => isActiveState(i.state)).length;
  const handled = s.incidents.filter((i) => ['RESOLVED', 'CLOSED'].includes(i.state)).length;
  const byId = Object.fromEntries(all.map((i) => [i.id, i]));
  return (
    <div>
      <PageHead title="Activity" sub="Everything Phoenix X noticed and did, in plain words. Tap any item for the full story." right={<div className="flex gap-2"><Chip tone="ok" dot>{handled} handled</Chip><Chip tone="ember" dot>{open} in progress</Chip></div>} />

      <h2 className="mb-3">What came up</h2>
      {s.incidents.length ? (
        <div className="space-y-3">
          {s.incidents.map((i, k) => (
            <motion.button key={i.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(k, 8) * 0.04 }} whileHover={{ y: -2 }} onClick={() => go('#/incidents/' + i.id)} className="panel flex w-full items-center gap-4 !p-5 text-left transition-shadow hover:shadow-lift">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2"><b className="font-display text-[18px]">{plain(i.title)}</b><SevChip s={i.severity} /><StateChip s={i.state} /></div>
                <p className="mt-1 text-[14.5px] text-sub">{byId[i.id] ? didLine(byId[i.id]) : 'Loading'}</p>
                <div className="mt-0.5 text-[12.5px] text-mute">{fmtDT(i.createdAt)}</div>
              </div>
              <ChevronRight size={20} className="shrink-0 text-mute" />
            </motion.button>
          ))}
        </div>
      ) : <Panel><Empty>Nothing has come up yet. When something does, it appears here and Phoenix X starts working on it.</Empty></Panel>}

      <h2 className="mb-3 mt-10">Play-by-play</h2>
      <Panel>
        {lines.length ? (
          <ul className="divide-y divide-line">
            {lines.map((a, k) => (
              <motion.li key={a.ts + a.text} initial={k < 3 ? { opacity: 0, y: -6 } : false} animate={{ opacity: 1, y: 0 }} className="flex cursor-pointer gap-4 py-3 first:pt-0 last:pb-0" onClick={() => go('#/incidents/' + a.incidentId)}>
                <span className="w-[74px] shrink-0 pt-0.5 font-mono text-[12.5px] text-mute">{new Date(a.ts).toLocaleTimeString([], { hour12: false })}</span>
                <span className={cx('mt-2 h-2 w-2 shrink-0 rounded-full', a.tone === 'ok' ? 'bg-calm' : a.tone === 'warn' ? 'bg-[#ffc15a]' : a.tone === 'bad' ? 'bg-danger' : 'bg-brand')} />
                <div className="min-w-0 flex-1 text-[15px] leading-snug">{a.text}</div>
              </motion.li>
            ))}
          </ul>
        ) : <Empty>Nothing yet. Run a practice attack from Home and every step shows up here.</Empty>}
      </Panel>
    </div>
  );
}
