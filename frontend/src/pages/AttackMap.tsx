import { useEffect, useState } from 'react';
import { AttackGraph, GraphLegend } from '../components/AttackGraph';
import { NodePanel } from '../components/shared';
import { Empty, PageHead, Panel } from '../components/ui';
import { useApp, useIncident } from '../lib/store';
import type { Any } from '../types';

export function AttackMap() {
  const { s } = useApp();
  const [id, setId] = useState<string | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  useEffect(() => { if (!id || !s.incidents.some((i) => i.id === id)) setId(s.incidents[0]?.id ?? null); }, [s.incidents, id]);
  const { d } = useIncident(id);
  const g = d?.investigation?.graph;
  const sub = 'Each icon is a person, computer, address or file. Lines show what touched what. The dashed red line is the attack path. Select an item for its evidence.';
  if (!s.incidents.length) return <div><PageHead title="Attack map" sub={sub} /><Panel><Empty>No incidents yet. Run the attack demo to draw a map.</Empty></Panel></div>;
  return (
    <div>
      <PageHead title="Attack map" sub={sub} right={<label className="flex items-center gap-2 text-[14px] text-sub">Incident<select className="field" value={id ?? ''} onChange={(e) => { setId(e.target.value); setSel(null); }}>{s.incidents.map((i) => <option key={i.id} value={i.id}>{i.id}: {i.title}</option>)}</select></label>} />
      {g?.nodes ? (
        <div className="grid gap-5 lg:grid-cols-[minmax(0,2.3fr)_minmax(0,1fr)]">
          <div>
            <AttackGraph g={g} sel={sel} onSelect={setSel} height={560} /><GraphLegend />
            <Panel className="mt-4"><h2 className="mb-3">The attack path</h2>
              <div className="flex flex-wrap items-center gap-2">{(g.attackPath || []).map((nid: string, k: number) => { const n = g.nodes.find((x: Any) => x.id === nid); return <span key={nid} className="inline-flex items-center gap-2">{k > 0 && <span className="text-mute">then</span>}<button className="rounded-lg border border-line bg-[#0c1f17] px-2.5 py-1 font-mono text-[12.5px] hover:border-brand" onClick={() => setSel(nid)}>{n?.label || nid}</button></span>; })}{!g.attackPath?.length && <span className="text-sub">No path identified yet</span>}</div>
            </Panel>
          </div>
          <NodePanel g={g} sel={sel} evidence={d.evidence?.items || []} />
        </div>
      ) : <Panel><Empty>Loading the map</Empty></Panel>}
    </div>
  );
}
