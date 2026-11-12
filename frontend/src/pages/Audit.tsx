import { useState } from 'react';
import { AuditTable, run } from '../components/shared';
import { Btn, PageHead, Panel } from '../components/ui';
import { api } from '../lib/api';
import { useApp } from '../lib/store';

export function Audit() {
  const { s } = useApp();
  const [f, setF] = useState('');
  const [res, setRes] = useState<{ ok: boolean; length: number; brokenAt?: number } | null>(null);
  const q = f.toLowerCase();
  const rows = s.audit.slice().reverse().filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q)).slice(0, 300);
  return (
    <div>
      <PageHead title="Activity log" sub="A tamper-evident record of every decision, action, approval and sign-in. If anyone edits an entry, the chain check fails." />
      <Panel className="p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3">
          <input aria-label="Filter" className="field w-[300px] max-w-full" placeholder="Filter by person, action or incident" value={f} onChange={(e) => setF(e.target.value)} />
          <Btn v="primary" size="sm" onClick={async () => { const r = await run(() => api('/api/audit/verify')); if (r) setRes(r); }}>Check the chain</Btn>
          {res && <span className={res.ok ? 'font-semibold text-calm' : 'font-semibold text-danger'}>{res.ok ? `Chain intact. ${res.length} entries.` : `Chain broken at entry ${res.brokenAt}`}</span>}
        </div>
        <AuditTable rows={rows} />
      </Panel>
    </div>
  );
}
