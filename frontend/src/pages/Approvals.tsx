import { DecisionPanel } from '../components/shared';
import { Chip, Empty, PageHead, Panel, Table } from '../components/ui';
import { fmtDT } from '../lib/format';
import { useAllDetails, useApp } from '../lib/store';
import type { Any } from '../types';

export function Approvals() {
  const { s } = useApp();
  const all = useAllDetails();
  const rows = all.flatMap((i) => i.containment.filter((a: Any) => ['executed', 'denied', 'rolled_back'].includes(a.status)).map((a: Any) => ({ ...a, inc: i.id, title: i.title, when: a.executedAt || i.approvals.find((p: Any) => p.actionId === a.id)?.ts }))).sort((a, b) => +new Date(b.when || 0) - +new Date(a.when || 0));
  const who = (a: Any) => (a.status === 'denied' ? 'You said no' : a.approvedBy && !String(a.approvedBy).startsWith('policy') ? 'You said yes' : 'Phoenix X, on its own');
  return (
    <div>
      <PageHead title="Needs you" sub="The few things only you can decide. Each one is a single tap, and you can always see why." />
      {s.approvals.length ? <DecisionPanel /> : <Panel className="mb-5"><Empty>All good. Nothing needs you right now. Phoenix X will put anything that does right here.</Empty></Panel>}
      <Panel className="p-0">
        <h2 className="px-5 pt-5">Already handled</h2>
        {rows.length ? (
          <Table head={['When', 'What', 'Decided by', 'Result']}>
            {rows.map((a: Any) => (
              <tr key={a.id}><td className="td whitespace-nowrap text-mute">{a.when ? fmtDT(a.when) : ''}</td><td className="td"><div>{a.description}</div><div className="text-[13px] text-mute">{a.title}</div></td><td className="td">{who(a)}</td>
                <td className="td">{a.status === 'executed' ? <Chip tone="ok">Done</Chip> : a.status === 'denied' ? <Chip>Not done</Chip> : <Chip>Undone</Chip>}</td></tr>
            ))}
          </Table>
        ) : <Empty>No decisions yet</Empty>}
      </Panel>
    </div>
  );
}
