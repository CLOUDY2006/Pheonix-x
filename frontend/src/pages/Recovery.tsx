import { RecoveryBlock } from '../components/shared';
import { Chip, Empty, PageHead, Panel, Table } from '../components/ui';
import { fmtDT } from '../lib/format';
import { useAllDetails, useApp } from '../lib/store';
import type { Any } from '../types';

export function Recovery() {
  const { s } = useApp();
  const all = useAllDetails().filter((i) => i.recovery.tasks.length || i.recovery.readiness.length);
  const bk = s.assets.backups || {};
  return (
    <div>
      <PageHead title="Recovery" sub="Whether backups exist, what has to be restored, and proof that everything works again. Restores happen inside the simulation." />
      <Panel className="mb-5 p-0"><h2 className="px-5 pt-5">Backups</h2>
        <Table head={['Computer', 'Backup', 'Taken', 'Checked', 'Tamper-proof', 'Size']}>
          {Object.keys(s.assets.hosts || {}).flatMap((h) => ((bk[h] as Any[]) || [{ none: true }]).map((b, k) => b.none
            ? <tr key={h}><td className="td font-mono text-[12.5px]">{h}</td><td className="td font-medium text-danger" colSpan={5}>No backup. Recovery would mean rebuilding by hand.</td></tr>
            : <tr key={h + b.id}><td className="td font-mono text-[12.5px]">{k ? '' : h}</td><td className="td font-mono text-[12.5px]">{b.id}</td><td className="td text-sub">{fmtDT(b.ts)}</td><td className="td">{b.verified ? <Chip tone="ok">Verified</Chip> : <Chip tone="warn">Not verified</Chip>}</td><td className="td">{b.immutable ? 'Yes' : 'No'}</td><td className="td">{b.sizeGB} GB</td></tr>))}
        </Table>
      </Panel>
      {all.length ? all.map((i) => <div key={i.id} className="mb-6"><h2 className="mb-3"><a className="link" href={`#/incidents/${i.id}`}>{i.title}</a></h2><RecoveryBlock i={i} /></div>) : <Panel><Empty>A recovery plan appears once an incident reaches that stage.</Empty></Panel>}
    </div>
  );
}
