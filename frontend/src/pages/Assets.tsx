import { Chip, Empty, PageHead, Panel, Table } from '../components/ui';
import { useApp } from '../lib/store';
import type { Any } from '../types';

export function Assets() {
  const a = useApp().s.assets as Any;
  if (!a.users) return <Empty>Loading</Empty>;
  return (
    <div>
      <PageHead title="Assets" sub="The simulated company. When Phoenix X contains an attack, you can see these things change." />
      <div className="mb-5 grid gap-5 lg:grid-cols-2">
        <Panel className="p-0"><h2 className="px-5 pt-5">People and accounts</h2>
          <Table head={['Account', 'Team', 'Status', 'Sessions', 'MFA']}>{Object.entries(a.users).map(([k, u]) => { const x = u as Any; return <tr key={k}><td className="td"><span className="font-mono text-[12.5px]">{k}</span><div className="text-[12.5px] text-mute">{x.role}</div></td><td className="td">{x.dept}</td><td className={`td font-semibold ${x.status === 'active' ? 'text-calm' : 'text-danger'}`}>{x.status}</td><td className="td">{x.sessions}</td><td className="td">{x.mfa ? 'On' : <span className="font-semibold text-warn">Off</span>}</td></tr>; })}</Table>
        </Panel>
        <Panel className="p-0"><h2 className="px-5 pt-5">Computers and servers</h2>
          <Table head={['Name', 'Kind', 'Where', 'Importance', 'State']}>{Object.entries(a.hosts).map(([k, h]) => { const x = h as Any; return <tr key={k}><td className="td font-mono text-[12.5px]">{k}</td><td className="td">{x.kind}</td><td className="td">{x.env === 'production' ? <Chip tone="warn">Production</Chip> : 'Test'}</td><td className="td">{x.criticality}</td><td className={`td font-semibold ${x.isolated ? 'text-danger' : 'text-calm'}`}>{x.status}{x.restoredFrom ? ', restored' : ''}</td></tr>; })}</Table>
        </Panel>
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <Panel><h2 className="mb-3">Data</h2>{Object.entries(a.resources).map(([k, r]) => { const x = r as Any; return <div key={k} className="my-2 flex items-center justify-between gap-2"><span className="break-all font-mono text-[12.5px]">{k}</span>{x.restricted ? <Chip tone="bad">Access limited</Chip> : <Chip>{x.sensitivity}</Chip>}</div>; })}</Panel>
        <Panel><h2 className="mb-3">Cloud</h2>
          {Object.entries(a.cloud.roles).map(([k, r]) => { const x = r as Any; return <div key={k} className="my-2 flex justify-between gap-2"><span className="font-mono text-[12.5px]">{k}</span><span className={`text-[13px] ${x.policies.some((p: string) => /Admin/.test(p)) ? 'font-semibold text-danger' : 'text-sub'}`}>{x.policies.join(', ') || 'No rights'}</span></div>; })}
          {Object.entries(a.cloud.buckets).map(([k, b]) => { const x = b as Any; return <div key={k} className="my-2 flex justify-between gap-2"><span className="break-all font-mono text-[12.5px]">{k}</span><span className={x.public ? 'font-semibold text-danger' : 'font-semibold text-calm'}>{x.public ? 'Public' : 'Private'}</span></div>; })}
          <div className="mt-3 flex justify-between"><span>Activity logging</span><b className={a.cloud.trailLogging ? 'text-calm' : 'text-danger'}>{a.cloud.trailLogging ? 'On' : 'Off'}</b></div>
        </Panel>
        <Panel><h2 className="mb-3">API keys</h2>{Object.entries(a.secrets || {}).map(([k, v]) => { const x = v as Any; return <div key={k} className="my-2 flex items-center justify-between gap-2"><span className="break-all font-mono text-[12.5px]">{k}</span><span className={x.status === 'active' ? 'font-semibold text-calm' : 'font-semibold text-danger'}>{x.status === 'active' ? 'Active' : 'Revoked'}</span></div>; })}<h2 className="mb-3 mt-5">Blocked addresses</h2>{a.blockedIPs.length ? a.blockedIPs.map((ip: string) => <div key={ip} className="my-1.5 font-mono text-[13px] font-semibold text-danger">{ip}</div>) : <p className="text-sub">No addresses are blocked</p>}</Panel>
      </div>
    </div>
  );
}
