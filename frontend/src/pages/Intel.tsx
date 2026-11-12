import { Search } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { IntelTable, run } from '../components/shared';
import { Btn, Chip, Empty, More, Note, PageHead, Panel, Table } from '../components/ui';
import { api } from '../lib/api';
import { useAllDetails, useApp } from '../lib/store';
import type { Any } from '../types';

export function Intel() {
  const { s } = useApp();
  const all = useAllDetails();
  const inds: Record<string, Any> = {};
  all.forEach((i) => (i.intel?.indicators || []).forEach((x: Any) => (inds[x.indicator] = x)));
  const mitre = s.analytics.mitre || {};
  const [type, setType] = useState('ip'), [val, setVal] = useState(''), [res, setRes] = useState<Any | null>(null);
  const [q, setQ] = useState(''), [kb, setKb] = useState<Any[] | null>(null);
  const look = async (e: FormEvent) => { e.preventDefault(); const r = await run(() => api('/api/intel/lookup', 'POST', { type, value: val })); if (r) setRes(r); };
  const ask = async (e: FormEvent) => { e.preventDefault(); const r = await run(() => api('/api/kb?q=' + encodeURIComponent(q))); if (r) setKb(r); };
  return (
    <div>
      <PageHead title="Threat lookup" sub={`Check whether an address, website or file is known to be bad. Source: ${s.integrations['Threat intel (VirusTotal)'] || 'sample list'}. Something we do not recognize is shown as “unknown”, never “malicious”.`} />
      <div className="mb-5 grid gap-5 lg:grid-cols-2">
        <Panel><h2 className="mb-3">Look up an indicator</h2>
          <form onSubmit={look} className="flex flex-wrap gap-2"><select aria-label="Type" className="field" value={type} onChange={(e) => setType(e.target.value)}><option value="ip">IP address</option><option value="domain">Website</option><option value="hash">File hash</option></select><input aria-label="Value" required className="field min-w-[140px] flex-1" placeholder="198.19.66.14" value={val} onChange={(e) => setVal(e.target.value)} /><Btn v="primary"><Search size={15} />Check</Btn></form>
          {res && <div className="mt-3"><IntelTable list={[res]} /></div>}
        </Panel>
        <Panel><h2 className="mb-3">Search the playbooks</h2>
          <form onSubmit={ask} className="flex gap-2"><input aria-label="Search" required className="field flex-1" placeholder="ransomware backup restore" value={q} onChange={(e) => setQ(e.target.value)} /><Btn v="primary">Search</Btn></form>
          <div className="mt-3 max-h-[240px] overflow-auto">{kb?.map((x) => <Note key={x.id}><b>{x.title}</b><div className="text-sub">{String(x.text).slice(0, 260)}…</div></Note>)}{kb && !kb.length && <p className="text-sub">No matches</p>}</div>
        </Panel>
      </div>
      <Panel className="mb-2 p-0"><h2 className="px-5 pt-5">Indicators seen so far ({Object.keys(inds).length})</h2><IntelTable list={Object.values(inds)} /></Panel>
      <More title="Attack techniques seen (MITRE ATT&CK)" hint="For security specialists">
        {Object.keys(mitre).length ? <Table head={['Code', 'Technique', 'Evidence', 'Incidents']}>{Object.entries(mitre).map(([k, v]) => { const m = v as Any; return <tr key={k}><td className="td"><Chip tone={m.status === 'evidence-supported' ? 'ok' : 'warn'}>{k}</Chip></td><td className="td">{m.name}</td><td className="td">{m.status === 'evidence-supported' ? 'Seen directly' : 'Possible, not proven'}</td><td className="td">{m.n}</td></tr>; })}</Table> : <Empty>None yet</Empty>}
      </More>
    </div>
  );
}
