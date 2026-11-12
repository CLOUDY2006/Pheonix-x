import { AnimatePresence, motion, type HTMLMotionProps, type Variants } from 'framer-motion';
import { ChevronDown, type LucideIcon } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { ALL_NAV } from '../lib/nav';
import { SEV, STATE_SHORT, TIER } from '../lib/format';
import { useCount, useRoute } from '../lib/store';

export const cx = (...a: (string | false | null | undefined)[]) => a.filter(Boolean).join(' ');
export const EASE = [0.22, 1, 0.36, 1] as const;

export function Panel({ className, children, ...p }: { className?: string; children: ReactNode } & React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cx('panel', className)} {...p}>{children}</div>;
}

const group: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.07, delayChildren: 0.05 } } };
const item: Variants = { hidden: { opacity: 0, y: 18 }, show: { opacity: 1, y: 0, transition: { duration: 0.55, ease: EASE } } };
export const Stagger = ({ children, className }: { children: ReactNode; className?: string }) => <motion.div className={className} variants={group} initial="hidden" animate="show">{children}</motion.div>;
export const Rise = ({ children, className }: { children: ReactNode; className?: string }) => <motion.div className={className} variants={item}>{children}</motion.div>;

export function Tile({ children, className, ...p }: { children: ReactNode; className?: string } & HTMLMotionProps<'div'>) {
  return <motion.div whileHover={{ y: -4 }} transition={{ type: 'spring', stiffness: 320, damping: 24 }} className={cx('panel transition-shadow hover:shadow-lift', className)} {...p}>{children}</motion.div>;
}

type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info' | 'ember';
const TONE: Record<Tone, string> = { neutral: 'bg-[#0c1f17] text-sub', ok: 'bg-calm-soft text-calm-dark', warn: 'bg-warn-soft text-warn', bad: 'bg-danger-soft text-[#ff8a8a]', info: 'bg-brand-soft text-brand', ember: 'bg-ember-soft text-ember-dark' };
const DOT: Record<Tone, string> = { neutral: 'bg-[#6f9384]', ok: 'bg-calm', warn: 'bg-[#ffc15a]', bad: 'bg-danger', info: 'bg-brand', ember: 'bg-ember' };
export function Chip({ tone = 'neutral', children, className, dot }: { tone?: Tone; children: ReactNode; className?: string; dot?: boolean }) {
  return <span className={cx('inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-3 py-1 text-[12.5px] font-semibold', TONE[tone], className)}>{dot && <span className={cx('h-1.5 w-1.5 rounded-full', DOT[tone])} />}{children}</span>;
}
const SEVT: Record<string, Tone> = { critical: 'bad', high: 'warn', medium: 'warn', low: 'ok', info: 'neutral' };
export const SevChip = ({ s }: { s: string }) => <Chip tone={SEVT[s] || 'neutral'} dot>{SEV[s] || s}</Chip>;
const TIERT: Record<string, Tone> = { automatic: 'ok', approval: 'warn', restricted: 'bad' };
export const TierChip = ({ t }: { t: string }) => <Chip tone={TIERT[t] || 'neutral'}>{TIER[t] || t}</Chip>;
export const StateChip = ({ s }: { s: string }) => { const [l, t] = STATE_SHORT[s] || [s, 'neutral']; return <Chip tone={t} dot>{l}</Chip>; };
export const OriginChip = ({ o }: { o: string }) => (o === 'ingested' ? <Chip tone="ok">Real data</Chip> : o === 'scenario' ? <Chip tone="bad">Test attack</Chip> : <Chip>Simulated</Chip>);

type V = 'primary' | 'ember' | 'ok' | 'danger' | 'ghost' | 'outline';
const BV: Record<V, string> = {
  primary: 'bg-ink text-onink hover:bg-ink-3',
  ember: 'bg-gradient-to-br from-[#ff7a45] to-[#ff4d5e] text-onink shadow-[0_12px_26px_-10px_rgba(255,90,60,.75)] hover:brightness-105',
  ok: 'bg-calm text-onink shadow-[0_12px_26px_-12px_rgba(18,163,127,.8)] hover:bg-calm-dark',
  danger: 'border border-[#6b2f33] bg-transparent text-[#ff8a8a] hover:bg-danger-soft',
  ghost: 'text-sub hover:bg-white/5',
  outline: 'border border-[#2a4a3b] bg-surface text-text hover:bg-[#0c1f17]',
};
export function Btn({ v = 'outline', size = 'md', className, ...p }: { v?: V; size?: 'sm' | 'md' | 'lg' } & HTMLMotionProps<'button'>) {
  return <motion.button whileTap={{ scale: 0.96 }} whileHover={p.disabled ? undefined : { y: -2 }} transition={{ type: 'spring', stiffness: 500, damping: 28 }}
    className={cx('inline-flex items-center justify-center gap-2 rounded-full font-semibold transition-[background,filter,box-shadow] disabled:cursor-not-allowed disabled:opacity-45', size === 'sm' ? 'px-4 py-1.5 text-[13px]' : size === 'lg' ? 'px-7 py-3.5 text-[15.5px]' : 'px-5 py-2.5 text-[14px]', BV[v], className)} {...p} />;
}

export function Toggle({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)} className={cx('relative h-7 w-12 shrink-0 rounded-full transition-colors disabled:opacity-45', checked ? 'bg-calm' : 'bg-[#2a4a3b]')}>
      <motion.span layout transition={{ type: 'spring', stiffness: 600, damping: 32 }} className={cx('absolute top-1 h-5 w-5 rounded-full bg-surface shadow', checked ? 'right-1' : 'left-1')} />
    </button>
  );
}

export function More({ title, hint, children, defaultOpen = false }: { title: ReactNode; hint?: string; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <div className="mt-4 rounded-3xl border border-line bg-surface shadow-soft">
      <button aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-6 py-4 text-left">
        <span className="font-semibold">{title}</span>{hint && <span className="hidden text-[13.5px] text-mute sm:inline">{hint}</span>}
        <motion.span animate={{ rotate: open ? 180 : 0 }} className="ml-auto grid h-8 w-8 place-items-center rounded-full bg-[#0c1f17] text-sub"><ChevronDown size={17} /></motion.span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div id={id} initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.3, ease: EASE }} className="overflow-hidden">
            <div className="px-6 pb-6">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export const Empty = ({ children }: { children: ReactNode }) => <div className="px-4 py-10 text-center text-mute">{children}</div>;

export function PageHead({ title, sub, right }: { title: string; sub?: ReactNode; right?: ReactNode }) {
  const { page } = useRoute();
  const Icon = ALL_NAV.find((i) => i[0] === page)?.[2];
  return (
    <div className="mb-7 flex flex-wrap items-start justify-between gap-4">
      <div className="flex items-start gap-4">
        {Icon && <motion.span initial={{ scale: 0.6, rotate: -12, opacity: 0 }} animate={{ scale: 1, rotate: 0, opacity: 1 }} transition={{ type: 'spring', stiffness: 260, damping: 16 }} className="mt-0.5 hidden h-12 w-12 shrink-0 place-items-center rounded-2xl bg-ink text-onink shadow-soft sm:grid"><Icon size={22} /></motion.span>}
        <div><h1>{title}</h1>{sub && <p className="mt-1.5 max-w-[66ch] text-[15.5px] text-sub">{sub}</p>}</div>
      </div>
      {right}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: [T, string][]; value: T; onChange: (t: T) => void }) {
  const id = useId();
  return (
    <div role="tablist" className="mb-6 inline-flex max-w-full gap-1 overflow-x-auto rounded-full bg-surface p-1.5 shadow-soft ring-1 ring-white/5">
      {tabs.map(([k, l]) => (
        <button key={k} role="tab" aria-selected={value === k} onClick={() => onChange(k)} className={cx('relative whitespace-nowrap rounded-full px-4 py-2 text-[14px] font-semibold transition-colors', value === k ? 'text-onink' : 'text-sub hover:text-text')}>
          {value === k && <motion.span layoutId={'tab' + id} className="absolute inset-0 rounded-full bg-ink" transition={{ type: 'spring', stiffness: 420, damping: 34 }} />}
          <span className="relative">{l}</span>
        </button>
      ))}
    </div>
  );
}

export function Stat({ value, label, suffix = '' }: { value: number | null | undefined; label: string; suffix?: string }) {
  const n = useCount(value ?? 0);
  return (
    <div className="px-5 py-4">
      <div className="font-display text-[30px] font-bold leading-none tracking-tight tabular-nums">{value == null ? <span className="text-[20px] text-mute">None yet</span> : n + suffix}</div>
      <div className="mt-1.5 text-[13px] text-mute">{label}</div>
    </div>
  );
}

export function StatTile({ value, label, suffix = '', tone, icon: Icon }: { value: number | null | undefined; label: string; suffix?: string; tone: 'brand' | 'calm' | 'ember'; icon: LucideIcon }) {
  const n = useCount(value ?? 0);
  const t = { brand: 'bg-brand-soft text-brand', calm: 'bg-calm-soft text-calm-dark', ember: 'bg-ember-soft text-ember-dark' }[tone];
  return (
    <Tile className="flex items-center gap-4 !p-5">
      <span className={cx('grid h-12 w-12 shrink-0 place-items-center rounded-2xl', t)}><Icon size={22} /></span>
      <div><div className="font-display text-[30px] font-bold leading-none tabular-nums">{value == null ? <span className="text-[19px] text-mute">None yet</span> : n + suffix}</div><div className="mt-1 text-[13px] text-mute">{label}</div></div>
    </Tile>
  );
}

export const Bar = ({ pct, tone = 'brand' }: { pct: number; tone?: 'brand' | 'calm' | 'ember' | 'danger' }) => (
  <div className="h-2.5 overflow-hidden rounded-full bg-[#14291f]"><motion.div className={cx('h-full rounded-full', { brand: 'bg-brand', calm: 'bg-calm', ember: 'bg-gradient-to-r from-[#ff7a45] to-[#ff4d5e]', danger: 'bg-danger' }[tone])} initial={false} animate={{ width: Math.max(0, Math.min(100, pct)) + '%' }} transition={{ duration: 0.7, ease: EASE }} /></div>
);

export const Note = ({ tone = 'neutral', children }: { tone?: 'neutral' | 'ok' | 'warn' | 'bad'; children: ReactNode }) => (
  <div className={cx('my-2 rounded-2xl px-4 py-3 text-[14px]', { neutral: 'bg-[#0c1f17]', ok: 'bg-calm-soft', warn: 'bg-warn-soft', bad: 'bg-danger-soft' }[tone])}>{children}</div>
);

export const Mono = ({ children, className }: { children: ReactNode; className?: string }) => <span className={cx('font-mono text-[12.5px]', className)}>{children}</span>;
export const Table = ({ head, children, className }: { head: string[]; children: ReactNode; className?: string }) => (
  <div className={cx('overflow-x-auto', className)}><table className="w-full border-collapse"><thead><tr>{head.map((h) => <th key={h} className="th">{h}</th>)}</tr></thead><tbody>{children}</tbody></table></div>
);
