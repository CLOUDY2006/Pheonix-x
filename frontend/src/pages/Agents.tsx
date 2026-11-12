import { motion } from 'framer-motion';
import { useState } from 'react';
import { AgentFlow } from '../components/AgentFlow';
import { Chip, Empty, PageHead, Panel } from '../components/ui';
import { AG_COL, AG_NAME, fmtT } from '../lib/format';
import { useApp } from '../lib/store';
import type { Any, AgentMsg } from '../types';

export const AGENT_INFO: Record<string, { role: string; does: string; in: string; out: string; tools: string; perm: string }> = {
  SENTINEL: { role: 'Spots threats', does: 'Watches every sign-in, file and network event and raises an alert when something looks wrong.', in: 'Security events from sign-ins, apps, computers, network, APIs, files and the cloud', out: 'An alert with a risk score from 0 to 100, severity, evidence and a recommended next step', tools: '20+ detection rules and a statistical anomaly model', perm: 'Can only read events. It cannot change any system.' },
  INVESTIGATOR: { role: 'Works out what happened', does: 'Connects the dots between alerts to build a timeline, find the likely way in and separate facts from guesses.', in: 'Alerts plus the stored events around them', out: 'Timeline, attack map, confirmed findings, hypotheses and a confidence level', tools: 'Event correlation, map builder, safe email analysis (links are never opened)', perm: 'Read-only. An AI-written summary can never change the facts.' },
  ORACLE: { role: 'Checks bad-actor lists', does: 'Looks up addresses, websites and files in threat databases. Something unknown is never treated as bad.', in: 'IP addresses, domains and file hashes from the incident', out: 'A verdict: malicious, suspicious, no detections or unknown', tools: 'VirusTotal when a key is set, otherwise a built-in sample list', perm: 'Only looks things up. It changes nothing.' },
  GUARDIAN: { role: 'Stops the damage', does: 'Plans safe actions such as blocking an address or suspending an account. Risky ones wait for your approval.', in: 'The investigation and threat lookups', out: 'A plan where each action is automatic, needs approval or is never automatic', tools: 'A short list of approved actions. No shell, no scripts.', perm: 'Every action is re-checked against the safety rules right before it runs.' },
  RECOVERY: { role: 'Gets things back to normal', does: 'Checks backups, lists restore tasks and confirms everything works again.', in: 'Affected systems, containment results and the backup list', out: 'A readiness report, recovery tasks and a verification report', tools: 'Simulated backup and restore, task tracker, verification checks', perm: 'Works only inside the simulation. No real files are touched.' },
  COMMANDER: { role: 'Runs the whole response', does: 'Coordinates the other helpers, tracks each step and asks you when a decision is needed.', in: 'Alerts and the results from every helper', out: 'The incident, its 12 steps, its priority, approvals and the final report', tools: 'Checks every message, scores priority, looks up playbooks, sends notices and tickets', perm: 'Only coordinates. If one helper fails, the rest of the response carries on.' },
};

export function MsgList({ list }: { list: AgentMsg[] }) {
  const [open, setOpen] = useState<number | null>(null);
  if (!list.length) return <Empty>No messages yet. Run a demo to see them.</Empty>;
  return (
    <ul className="space-y-2">{list.map((m, i) => (
      <li key={m.ts + i} className="rounded-xl border border-line">
        <button className="flex w-full flex-wrap items-center gap-2 px-3.5 py-2.5 text-left text-[13.5px]" onClick={() => setOpen(open === i ? null : i)} aria-expanded={open === i}>
          <b style={{ color: AG_COL[m.from] }}>{AG_NAME[m.from] || m.from}</b><span className="text-mute">told</span><b style={{ color: AG_COL[m.to] }}>{AG_NAME[m.to] || m.to}</b><Chip>{String(m.type).replace(/_/g, ' ')}</Chip><span className="ml-auto text-mute">{fmtT(m.ts)}</span>
        </button>
        {open === i && <pre className="mx-3.5 mb-3 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-[#0c1f17] p-3 font-mono text-[12px]">{JSON.stringify(m.payload, null, 1)}</pre>}
      </li>
    ))}</ul>
  );
}

export function Agents() {
  const { s } = useApp();
  const roles = Object.fromEntries(Object.entries(AGENT_INFO).map(([k, v]) => [k, v.role]));
  return (
    <div>
      <PageHead title="AI helpers" sub="Six helpers share the work. They only pass checked messages through the Commander, and none can run commands on their own." />
      <AgentFlow agents={s.agents as Record<string, Any>} roles={roles} />
      <div className="mt-5 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
        {Object.entries(AGENT_INFO).map(([k, a], i) => {
          const st = s.agents[k] || { runs: 0, failures: 0, state: 'idle' };
          return (
            <motion.div key={k} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
              <Panel className="h-full">
                <div className="mb-3 flex items-center gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl text-[13px] font-bold text-white" style={{ background: AG_COL[k] }}>{k.slice(0, 2)}</div><div><b className="block leading-tight">{AG_NAME[k]}</b><span className="text-[13.5px] text-sub">{a.role}</span></div></div>
                <p className="text-[14px] text-sub">{a.does}</p>
                <p className="my-2 text-[14px]">{st.state === 'working' ? <span className="font-medium text-ember-dark">Now: {st.current || 'working'}</span> : <span className="text-mute">Idle. {st.runs} jobs done.</span>}</p>
                <details className="text-[13.5px]"><summary className="cursor-pointer text-mute hover:text-text">Technical details</summary>
                  <dl className="mt-2 grid grid-cols-[80px_1fr] gap-x-3 gap-y-1.5"><dt className="text-mute">Receives</dt><dd>{a.in}</dd><dt className="text-mute">Produces</dt><dd>{a.out}</dd><dt className="text-mute">Uses</dt><dd>{a.tools}</dd><dt className="text-mute">Limits</dt><dd>{a.perm}</dd><dt className="text-mute">Record</dt><dd>{st.runs} runs, {st.failures} failed{st.lastMs ? `, last took ${st.lastMs} ms` : ''}</dd></dl>
                </details>
              </Panel>
            </motion.div>
          );
        })}
      </div>
      <Panel className="mt-5"><h2 className="mb-1">Messages between helpers</h2><p className="mb-3 text-sub">Select a message to see its full contents.</p><div className="max-h-[520px] overflow-auto"><MsgList list={s.messages.slice().reverse()} /></div></Panel>
    </div>
  );
}
