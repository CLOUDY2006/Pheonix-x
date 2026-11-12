import { AnimatePresence, motion } from 'framer-motion';
import { ArrowRight, Play, ShieldCheck, Timer, X, Zap } from 'lucide-react';
import { useState } from 'react';
import { Area, AreaChart, ResponsiveContainer } from 'recharts';
import { AttackGraph } from '../components/AttackGraph';
import { StageTrack, StepList } from '../components/StageTrack';
import { AgentLine, DecisionPanel, EventFeed, IncTable, NodePanel, Timeline, run, useApproveAll, useLaunch } from '../components/shared';
import { Bar, Btn, Chip, EASE, Empty, More, Rise, Stagger, StatTile, Tile, Toggle, cx } from '../components/ui';
import { AGENT_INFO, MsgList } from './Agents';
import { AG_NAME, buildActivity, isActiveState, plain, scoreAreas } from '../lib/format';
import { api } from '../lib/api';
import { go, useAllDetails, useApp, useCan, useIncident } from '../lib/store';
import type { Any } from '../types';

type Tone = 'ok' | 'warn' | 'bad';
const TONE_COL: Record<Tone, string> = { ok: '#2ee6a6', warn: '#ffc15a', bad: '#ff9a6b' };

function Ring({ score, tone }: { score: number; tone: Tone }) {
  const c = TONE_COL[tone];
  return (
    <div className="relative h-[176px] w-[176px] shrink-0" aria-label={`Safety score ${score} out of 100`} role="img">
      <motion.span className="absolute inset-0 rounded-full border-2" style={{ borderColor: c }} animate={{ scale: [0.92, 1.28], opacity: [0.55, 0] }} transition={{ duration: 3.2, repeat: Infinity, ease: 'easeOut' }} />
      <motion.div className="absolute inset-0 rounded-full" initial={false} animate={{ background: `conic-gradient(${c} 0 ${score}%, #14291f 0)` }} transition={{ duration: 0.9 }} />
      <div className="absolute inset-[14px] grid place-content-center rounded-full bg-surface text-center"><b className="font-display text-[54px] leading-none">{score}</b><span className="text-[12px] text-mute">out of 100</span></div>
    </div>
  );
}

export function Overview() {
  const { s, dispatch } = useApp();
  const { act, admin } = useCan();
  const launch = useLaunch();
  const all = useAllDetails();
  const latest = s.incidents[0];
  const { d } = useIncident(latest?.id);
  const [sel, setSel] = useState<string | null>(null);

  const n = s.approvals.length;
  const active = s.incidents.filter((i) => isActiveState(i.state));
  const handledOne = s.incidents.find((i) => ['RESOLVED', 'CLOSED'].includes(i.state));
  let tone: Tone = 'ok', answer = 'Yes. All clear.', line = 'Nothing suspicious right now. Phoenix X keeps watching in the background.', cta: { label: string; to: string } | null = null;
  if (n) { tone = 'warn'; answer = n === 1 ? 'Not yet. One thing needs you.' : `Not yet. ${n} things need you.`; line = 'Phoenix X is holding off until you say yes or no. It takes one tap.'; }
  else if (active.length) { tone = 'bad'; answer = 'Mostly. Phoenix X is on it.'; line = `${plain(active[0].title)}. You do not need to do anything right now.`; cta = { label: 'Watch it work', to: '#/incidents/' + active[0].id }; }
  else if (handledOne) { answer = 'Yes. Phoenix X handled it.'; line = `It dealt with “${plain(handledOne.title)}”. See exactly what it did.`; cta = { label: 'See what it did', to: '#/incidents/' + handledOne.id }; }
  const compact = n > 0;
  const approveAll = useApproveAll();
  const [welcome, setWelcome] = useState(() => { try { return localStorage.getItem('phx_welcome') !== 'done'; } catch { return false; } });
  const closeWelcome = () => { try { localStorage.setItem('phx_welcome', 'done'); } catch { /* private mode */ } setWelcome(false); };

  const m = s.metrics, mode: string = s.autonomy?.mode || 'balanced';
  const auto = mode === 'full';
  const areas = scoreAreas(all);
  const score = active.length ? Math.max(0, Math.min(100, 100 - (m.riskScore ?? 0))) : 100;
  const verdict = n ? 'Needs you' : active.length ? 'Being handled' : score >= 85 ? 'Strong' : score >= 60 ? 'Fair' : 'At risk';
  const worst = active.slice().sort((a, b) => b.riskScore - a.riskScore)[0];
  const activity = buildActivity(all).slice(0, 5);
  const handledCount = s.incidents.filter((i) => ['RESOLVED', 'CLOSED'].includes(i.state)).length;
  const taskT = s.incidents.reduce((a, i) => a + i.tasks.total, 0), taskD = s.incidents.reduce((a, i) => a + i.tasks.done, 0);
  const g = d?.investigation?.graph;
  const spark = (s.analytics.series || []).map((p: { generated: number; scenario: number; ingested: number }, i: number) => ({ i, n: p.generated + p.scenario + p.ingested }));
  const setMode = async (k: string) => { const r = await run(() => api('/api/autonomy', 'POST', { mode: k }), k === 'full' ? 'Autopilot is on. Phoenix X will handle it from here.' : 'Okay. Phoenix X will ask you before risky actions.'); if (r) dispatch({ t: 'autonomy', d: r }); };
  const demo = s.mode === 'demo' && s.settings.allowScenarios !== false;

  let primary: { label: string; hint: string; onClick: () => void; v: 'ember' | 'ok' | 'outline'; disabled?: boolean; icon?: boolean } | null = null;
  if (n && admin) primary = { label: n === 1 ? 'Approve it' : `Approve all ${n}`, hint: 'Phoenix X carries out what it suggested. You can still review each one below.', onClick: n === 1 ? () => document.getElementById('decisions')?.scrollIntoView({ behavior: 'smooth' }) : approveAll, v: 'ok' };
  else if (n) primary = { label: 'Ask an admin to approve', hint: 'Only an admin can approve actions.', onClick: () => {}, v: 'outline', disabled: true };
  else if (active.length) primary = { label: 'Watch it work', hint: 'You do not need to do anything. This just shows what it is doing.', onClick: () => go('#/incidents/' + active[0].id), v: 'outline' };
  else if (handledOne) primary = { label: 'See what it did', hint: 'A plain-English story of what happened and what was done.', onClick: () => go('#/incidents/' + handledOne.id), v: 'outline' };
  else if (demo) primary = { label: 'Run a practice attack', hint: 'A safe, fake attack so you can watch Phoenix X deal with it. Takes 3 to 5 minutes.', onClick: () => launch('signature'), v: welcome && admin ? 'outline' : 'ember', disabled: !act, icon: true };
  else primary = { label: 'Connect your first app', hint: 'Tell Phoenix X where your logs live. It does the rest.', onClick: () => { location.href = '/classic/#/connect'; }, v: 'ember' };
  const showDemoLink = demo && (n > 0 || active.length > 0 || !!handledOne);

  return (
    <div>
      <AnimatePresence>
        {welcome && admin && (
          <motion.div initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, height: 0, marginBottom: 0 }} className="relative mb-6 rounded-3xl border border-[#1d5a43] bg-surface-2 p-6 pr-14">
            <button aria-label="Close" onClick={closeWelcome} className="absolute right-4 top-4 rounded-full p-2 text-mute hover:bg-white/5"><X size={18} /></button>
            <h2 className="font-display text-[22px]">Welcome. Phoenix X can handle everything for you.</h2>
            <ol className="mt-3 grid gap-3 text-[14.5px] text-sub md:grid-cols-3">
              <li><b className="text-text">1. It watches.</b> Every sign-in, server and cloud app, all day.</li>
              <li><b className="text-text">2. It fixes.</b> When something is wrong it stops it, in seconds, and explains why.</li>
              <li><b className="text-text">3. It asks only when needed.</b> Anything risky waits for one tap from you.</li>
            </ol>
            <div className="mt-5 flex flex-wrap items-center gap-3"><Btn v="ember" onClick={async () => { await setMode('full'); closeWelcome(); }}>Turn on Autopilot (recommended)</Btn><Btn v="outline" onClick={closeWelcome}>Keep asking me first</Btn><span className="text-[13px] text-mute">You can change this any time in Settings.</span></div>
          </motion.div>
        )}
      </AnimatePresence>

      <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, ease: EASE }} className={cx('mb-6 grid items-center gap-10 rounded-[36px] border border-line bg-surface shadow-soft', compact ? 'p-7 lg:grid-cols-1' : 'p-7 md:p-12 lg:grid-cols-[1.1fr_1fr]')}>
        <div>
          <div className="eyebrow">Autonomous security operations</div>
          <h1 className={cx('mt-5 font-display font-bold leading-[1.02] tracking-tight', compact ? 'text-[38px] md:text-[48px]' : 'text-[44px] md:text-[64px]')}>
            Are we safe?<br />
            <AnimatePresence mode="wait"><motion.span key={answer} className="acc" style={{ color: TONE_COL[tone], fontSize: '1.08em' }} initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.45, ease: EASE }}>{answer}</motion.span></AnimatePresence>
          </h1>
          <p className="mt-5 max-w-[46ch] text-[17px] text-sub">{line}</p>
          {primary && <div className="mt-7"><Btn v={primary.v} size="lg" onClick={primary.onClick} disabled={primary.disabled}>{primary.icon && <Play size={16} fill="currentColor" />}{primary.label}{!primary.icon && !primary.disabled && <ArrowRight size={17} />}</Btn><p className="mt-3 max-w-[48ch] text-[13.5px] text-mute">{primary.hint}</p></div>}
          {showDemoLink && <button onClick={() => launch('signature')} disabled={!act} className="mt-3 text-[13.5px] font-medium text-mute underline-offset-4 hover:text-text hover:underline">Run a practice attack instead</button>}
        </div>
        {!compact && (
          <div className="rounded-3xl border border-line bg-canvas p-7">
            <div className="flex flex-wrap items-center gap-7">
              <Ring score={score} tone={tone} />
              <div className="min-w-[180px] flex-1"><div className="text-[13px] text-mute">Safety score</div><div className="font-display text-[28px] font-bold">{verdict}</div><p className="mt-1 text-[14px] text-sub">{handledCount ? `${handledCount} ${handledCount === 1 ? 'threat was' : 'threats were'} handled so far.` : 'No threats so far.'}</p></div>
            </div>
            <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {areas.map(([k, v]) => <div key={k} className="rounded-2xl bg-surface-2 p-3.5"><div className="text-[12.5px] text-mute">{k}</div><b className={cx('font-display text-[24px]', v < 60 ? 'text-danger' : v < 90 ? 'text-warn' : '')}>{v}</b></div>)}
            </div>
            <p className="mt-5 border-t border-line pt-4 text-[14px] text-sub"><b className="text-text">{score >= 100 ? 'Nothing to improve.' : 'Why not 100?'}</b> {score >= 100 ? '' : worst ? `${plain(worst.title)} is still open.` : ''}</p>
          </div>
        )}
      </motion.section>

      <DecisionPanel title="Waiting for you" />

      <Stagger className="grid gap-5 lg:grid-cols-12">
        <Rise className="lg:col-span-7">
          <Tile className="h-full">
            <div className="mb-4 flex items-center justify-between"><h2>What Phoenix X did</h2><a className="link text-[14px]" href="#/activity">See everything</a></div>
            {activity.length ? (
              <ul className="space-y-4">{activity.map((a, k) => (
                <motion.li key={a.ts + a.text} initial={k < 2 ? { opacity: 0, x: -10 } : false} animate={{ opacity: 1, x: 0 }} className="flex gap-3.5">
                  <span className={cx('mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-xl', a.tone === 'ok' ? 'bg-calm-soft text-calm-dark' : a.tone === 'warn' ? 'bg-warn-soft text-warn' : a.tone === 'bad' ? 'bg-danger-soft text-danger' : 'bg-brand-soft text-brand')}><Zap size={15} /></span>
                  <div className="min-w-0"><div className="text-[14.5px] leading-snug">{a.text}</div><div className="mt-0.5 text-[12.5px] text-mute">{new Date(a.ts).toLocaleTimeString([], { hour12: false })}</div></div>
                </motion.li>
              ))}</ul>
            ) : <Empty>Nothing has needed attention yet. When something does, it shows up here in plain words.</Empty>}
          </Tile>
        </Rise>
        <Rise className="lg:col-span-5">
          <Tile className="h-full">
            <div className="flex items-start justify-between gap-4">
              <div><div className="flex items-center gap-2"><ShieldCheck size={18} className="text-calm" /><h2>Autopilot</h2></div><p className="mt-1.5 text-[14.5px] text-sub">{auto ? 'On. Phoenix X handles everything it can. It only asks you when it truly cannot act alone.' : mode === 'watch' ? 'Off. Phoenix X only watches and recommends. You do everything yourself.' : 'Off. Phoenix X handles the safe things and asks you before risky ones.'}</p></div>
              <Toggle label="Autopilot" checked={auto} disabled={!admin} onChange={(v) => setMode(v ? 'full' : 'balanced')} />
            </div>
            <ul className="mt-4 space-y-1.5 text-[13.5px] text-sub"><li>Blocks bad addresses and ends stolen sessions</li><li>Suspends hacked accounts and fixes risky settings</li><li className="text-text">Never deletes data, wipes or shuts down machines</li></ul>
            <a className="link mt-4 inline-block text-[14px]" href="#/settings">Fine-tune in Settings</a>
          </Tile>
        </Rise>
      </Stagger>

      <More title="See details" hint="Numbers, progress, attack map, helpers">
        <div className="mb-5 grid gap-5 md:grid-cols-3">
          <StatTile value={m.eventsToday ?? 0} label="Events checked" tone="brand" icon={Zap} />
          <StatTile value={handledCount} label="Incidents handled" tone="calm" icon={ShieldCheck} />
          <StatTile value={m.avgContainSec ?? null} suffix="s" label="Average time to contain" tone="ember" icon={Timer} />
        </div>
        {latest && <><h3 className="mb-3 font-semibold">Progress of the latest incident</h3><div className="mb-6 rounded-2xl border border-line p-5"><StageTrack workflow={latest.workflow} /></div><StepList workflow={latest.workflow} /></>}
        <div className="mt-6 grid gap-5 lg:grid-cols-2">
          <div className="overflow-hidden rounded-2xl border border-line"><h3 className="px-5 pt-4 font-semibold">Recent incidents</h3><IncTable list={s.incidents.slice(0, 5)} /></div>
          <div className="overflow-hidden rounded-2xl border border-line"><div className="flex items-center justify-between px-5 pt-4"><h3 className="font-semibold">Live activity</h3><Chip tone="info" dot>{m.eventsToday ?? 0} checked</Chip></div><div className="h-[56px] px-2"><ResponsiveContainer width="100%" height="100%"><AreaChart data={spark} margin={{ top: 6, right: 0, left: 0, bottom: 0 }}><defs><linearGradient id="pulse" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#2ee6a6" stopOpacity=".35" /><stop offset="1" stopColor="#2ee6a6" stopOpacity="0" /></linearGradient></defs><Area type="monotone" dataKey="n" stroke="#2ee6a6" strokeWidth={2.5} fill="url(#pulse)" isAnimationActive /></AreaChart></ResponsiveContainer></div><EventFeed events={s.events} max={20} height={210} /></div>
        </div>
        <h3 className="mb-2 mt-6 font-semibold">Attack map</h3>
        {g ? <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]"><AttackGraph g={g} sel={sel} onSelect={setSel} height={380} /><NodePanel g={g} sel={sel} evidence={d.evidence?.items || []} /></div> : <Empty>No attack to show yet</Empty>}
        <h3 className="mb-2 mt-6 font-semibold">Timeline</h3>{d?.investigation ? <Timeline items={d.investigation.timeline} /> : <Empty>The timeline appears once an incident has been investigated.</Empty>}
        <div className="mt-6 grid gap-6 md:grid-cols-2">
          <div><h3 className="mb-1 font-semibold">AI helpers</h3>{Object.keys(AGENT_INFO).map((k) => <AgentLine key={k} k={k} name={AG_NAME[k]} role={AGENT_INFO[k].role} state={s.agents[k]?.state} current={s.agents[k]?.current} />)}</div>
          <div><h3 className="mb-2 font-semibold">Recovery progress</h3><div className="mb-2 flex justify-between text-sub"><span>{taskD} of {taskT} tasks done</span><b className="text-text">{taskT ? Math.round((taskD / taskT) * 100) : 0}%</b></div><Bar pct={taskT ? (taskD / taskT) * 100 : 0} tone="calm" /></div>
        </div>
        <h3 className="mb-2 mt-6 font-semibold">Messages between helpers</h3><MsgList list={s.messages.slice(-8).reverse() as Any[]} />
      </More>
    </div>
  );
}
