import { AnimatePresence, motion } from 'framer-motion';
import { LogOut } from 'lucide-react';
import type { ReactNode } from 'react';
import { ADV, MAIN, type NavItem } from '../lib/nav';
import { useApp } from '../lib/store';
import { Chip, cx } from './ui';

export const Logo = ({ size = 38 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden><rect width="32" height="32" rx="10" fill="#0b1220" /><path d="M16 5c2 5 7 7 7 12a7 7 0 0 1-14 0c0-2.5 1-4.5 2.5-6 0 2.5 1.5 3.5 2.5 3.5-1.5-4 0-7 2-9.5z" fill="#ff6a3d" /></svg>
);

function Backdrop() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden" aria-hidden>
      <motion.div className="absolute -right-40 -top-40 h-[520px] w-[520px] rounded-full bg-[#ff9a6b]/25 blur-3xl" animate={{ x: [0, -50, 0], y: [0, 40, 0] }} transition={{ duration: 18, repeat: Infinity, ease: 'easeInOut' }} />
      <motion.div className="absolute -bottom-48 -left-32 h-[560px] w-[560px] rounded-full bg-[#34d3a0]/20 blur-3xl" animate={{ x: [0, 60, 0], y: [0, -40, 0] }} transition={{ duration: 22, repeat: Infinity, ease: 'easeInOut' }} />
    </div>
  );
}

function SideLink({ it, active, badge }: { it: NavItem; active: boolean; badge?: number }) {
  const [k, label, Icon, hint] = it;
  return (
    <a href={`#/${k}`} aria-current={active ? 'page' : undefined} className={cx('relative flex items-center gap-3 rounded-2xl px-3.5 py-3 text-[15px] font-semibold transition-colors', active ? 'text-onink' : 'text-sub hover:bg-surface-2 hover:text-text')}>
      {active && <motion.span layoutId="sidepill" className="absolute inset-0 rounded-2xl bg-ink" transition={{ type: 'spring', stiffness: 420, damping: 34 }} />}
      <Icon size={20} className={cx('relative shrink-0', active && 'text-[#ff8a5c]')} /><span className="relative leading-tight">{label}{hint && <span className={cx('block text-[12px] font-normal', active ? 'text-onink/60' : 'text-mute')}>{hint}</span>}</span>
      {!!badge && <motion.span key={badge} initial={{ scale: 0.4 }} animate={{ scale: 1 }} className="relative ml-auto rounded-full bg-ember px-2 text-[12px] font-bold leading-5 text-onink">{badge}</motion.span>}
    </a>
  );
}

function BottomLink({ it, active, badge }: { it: NavItem; active: boolean; badge?: number }) {
  const [k, label, Icon] = it;
  return (
    <a href={`#/${k}`} aria-current={active ? 'page' : undefined} className={cx('relative flex flex-1 flex-col items-center gap-0.5 rounded-2xl py-2 text-[11px] font-semibold', active ? 'text-onink' : 'text-mute')}>
      {active && <motion.span layoutId="bottompill" className="absolute inset-0.5 rounded-2xl bg-ink" transition={{ type: 'spring', stiffness: 420, damping: 34 }} />}
      <Icon size={20} className={cx('relative', active && 'text-[#ff8a5c]')} /><span className="relative">{label}</span>
      {!!badge && <span className="absolute right-3 top-1 rounded-full bg-ember px-1.5 text-[10px] font-bold leading-4 text-onink">{badge}</span>}
    </a>
  );
}

export function Shell({ page, children }: { page: string; children: ReactNode }) {
  const { s, me, live, narr, logout } = useApp();
  const activeKey = ADV.some((x) => x[0] === page) ? 'advanced' : page === 'incidents' ? 'activity' : page;
  const badge: Record<string, number> = { approvals: s.approvals.length, activity: s.metrics.activeIncidents || 0 };
  return (
    <div className="min-h-screen lg:grid lg:h-screen lg:grid-cols-[288px_minmax(0,1fr)]">
      <Backdrop />
      <aside className="hidden p-4 lg:block">
        <div className="flex h-full flex-col rounded-[30px] bg-surface p-4 shadow-soft ring-1 ring-white/5">
          <div className="flex items-center gap-3 px-2 pb-5 pt-2"><Logo /><div><div className="font-display text-[20px] font-bold leading-none">Phoenix X</div><div className="mt-1 text-[12px] leading-none text-mute">Security that explains itself</div></div></div>
          <nav aria-label="Main" className="flex-1 space-y-1">{MAIN.map((it) => <SideLink key={it[0]} it={it} active={activeKey === it[0]} badge={badge[it[0]]} />)}</nav>
          <div className="flex items-center gap-3 rounded-2xl bg-surface-2 p-3">
            <div className="grid h-10 w-10 place-items-center rounded-full bg-ink font-display text-[16px] font-bold uppercase text-onink">{me?.user.charAt(0)}</div>
            <div className="min-w-0 flex-1"><div className="truncate text-[14px] font-semibold">{me?.user}</div><div className="flex items-center gap-1.5 text-[12px] text-mute"><span className={cx('h-1.5 w-1.5 rounded-full', live ? 'bg-calm' : 'bg-[#2a4a3b]')} />{live ? 'Live updates on' : 'Reconnecting'}</div></div>
            <button onClick={logout} aria-label="Sign out" className="rounded-xl p-2 text-mute hover:bg-surface hover:text-text"><LogOut size={17} /></button>
          </div>
        </div>
      </aside>
      <main id="main" className="min-w-0 lg:h-screen lg:overflow-y-auto">
        <header className="mx-auto flex max-w-[1180px] items-center justify-between px-5 py-4 lg:px-8 lg:py-5">
          <div className="flex items-center gap-2.5 lg:hidden"><Logo size={32} /><span className="font-display text-[18px] font-bold">Phoenix X</span></div>
          <span className="hidden text-[13.5px] font-medium text-mute lg:block">{[...MAIN, ...ADV].find((i) => i[0] === (page === 'incidents' ? 'activity' : page))?.[1]}</span>
          <div className="flex items-center gap-3"><Chip tone="info" dot>Safe simulation</Chip><button onClick={logout} aria-label="Sign out" className="rounded-full p-2 text-mute hover:bg-white/5 lg:hidden"><LogOut size={18} /></button></div>
        </header>
        <AnimatePresence>
          {narr && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="mx-auto max-w-[1180px] overflow-hidden px-5 lg:px-8" role="status">
              <div className="mb-4 flex items-center gap-3 rounded-2xl bg-brand-soft px-5 py-3 text-[14px] text-[#b9ccff]"><span className="relative flex h-2.5 w-2.5"><span className="absolute inline-flex h-full w-full animate-ping2 rounded-full bg-brand/60" /><span className="relative h-2.5 w-2.5 rounded-full bg-brand" /></span><span><b>Demo running.</b> {narr.text}</span></div>
            </motion.div>
          )}
        </AnimatePresence>
        <motion.div key={page} initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }} className="mx-auto max-w-[1180px] px-5 pb-28 lg:px-8 lg:pb-16">
          {children}
        </motion.div>
      </main>
      <nav aria-label="Main" className="fixed inset-x-3 bottom-3 z-30 flex rounded-[26px] bg-surface/95 p-1.5 shadow-lift ring-1 ring-white/5 backdrop-blur lg:hidden">
        {MAIN.map((it) => <BottomLink key={it[0]} it={it} active={activeKey === it[0]} badge={badge[it[0]]} />)}
      </nav>
    </div>
  );
}
