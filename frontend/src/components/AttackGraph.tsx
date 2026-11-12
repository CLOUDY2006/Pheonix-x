import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from '@xyflow/react';
import { AlertTriangle, AppWindow, FileText, Globe, Laptop, Network, Server, User, type LucideIcon } from 'lucide-react';
import { useMemo } from 'react';
import type { Any } from '../types';
import { cx } from './ui';

export const KIND_ICON: Record<string, LucideIcon> = { user: User, device: Laptop, server: Server, ip: Network, domain: Globe, file: FileText, application: AppWindow, event: AlertTriangle };
export const KIND_NAME: Record<string, string> = { user: 'Person', device: 'Computer', server: 'Server', ip: 'Network address', domain: 'Website', file: 'File', application: 'App or service', event: 'Security event' };
export const KIND_COL: Record<string, string> = { user: '#7ea1ff', device: '#2ee6a6', server: '#0f766e', ip: '#c2570c', domain: '#c2570c', file: '#b3cfc3', application: '#7a4fe0', event: '#ff6b6b' };
const BAND: Record<string, number> = { ip: 20, domain: 20, user: 140, event: 270, device: 410, server: 410, file: 520, application: 520 };

function EntityNode({ data }: NodeProps) {
  const d = data as Any;
  const Icon = KIND_ICON[d.kind] || User;
  return (
    <div className="flex w-[104px] flex-col items-center">
      <div className={cx('relative grid h-11 w-11 place-items-center rounded-xl border-2 bg-surface transition-shadow', d.suspicious && 'shadow-[0_0_0_6px_rgba(217,45,52,.13)]', d.sel && 'ring-2 ring-brand ring-offset-2')} style={{ borderColor: d.mal ? '#ff6b6b' : d.color, color: d.color }}>
        <Icon size={20} />
        <Handle type="target" position={Position.Top} style={{ opacity: 0, top: '50%', left: '50%' }} isConnectable={false} />
        <Handle type="source" position={Position.Top} style={{ opacity: 0, top: '50%', left: '50%' }} isConnectable={false} />
      </div>
      <div className="mt-1.5 max-w-[104px] break-words text-center text-[12px] leading-tight text-sub">{d.label}</div>
    </div>
  );
}
const nodeTypes = { entity: EntityNode };

export function AttackGraph({ g, sel, onSelect, height = 520 }: { g: Any; sel: string | null; onSelect: (id: string) => void; height?: number }) {
  const { nodes, edges } = useMemo(() => {
    const ev = g.nodes.filter((n: Any) => n.kind === 'event').sort((a: Any, b: Any) => +new Date(a.ts) - +new Date(b.ts));
    const pos: Record<string, { x: number; y: number }> = {};
    ev.forEach((n: Any, i: number) => (pos[n.id] = { x: i * 88, y: BAND.event + [-46, 0, 46][i % 3] }));
    const adj: Record<string, string[]> = {};
    g.edges.filter((e: Any) => !e.path).forEach((e: Any) => (adj[e.from] ||= []).push(e.to));
    const bands: Record<number, Any[]> = {};
    g.nodes.filter((n: Any) => n.kind !== 'event').forEach((n: Any) => {
      const xs = (adj[n.id] || []).map((t) => pos[t]?.x).filter((x) => x != null) as number[];
      n._x = xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : (ev.length * 88) / 2;
      (bands[BAND[n.kind] ?? 590] ||= []).push(n);
    });
    Object.entries(bands).forEach(([y, arr]) => { arr.sort((a, b) => a._x - b._x); let last = -1e9; arr.forEach((n, i) => { n._x = Math.max(n._x, last + 112); last = n._x; pos[n.id] = { x: n._x, y: +y + (i % 2 && +y !== 140 ? 28 : 0) }; }); });
    const nodes: Node[] = g.nodes.filter((n: Any) => pos[n.id]).map((n: Any) => ({ id: n.id, type: 'entity', position: { x: pos[n.id].x - 52, y: pos[n.id].y }, data: { ...n, color: KIND_COL[n.kind] || '#8fb3a4', mal: n.intel?.verdict === 'malicious', sel: sel === n.id }, draggable: true }));
    const edges: Edge[] = g.edges.filter((e: Any) => pos[e.from] && pos[e.to]).map((e: Any, i: number) => ({
      id: 'e' + i, source: e.from, target: e.to, type: 'straight', animated: !!e.path,
      style: { stroke: e.path ? '#ff6b6b' : '#2f5a47', strokeWidth: e.path ? 2.4 : 1.3, strokeDasharray: e.path ? '7 5' : undefined },
      markerEnd: e.path ? { type: MarkerType.ArrowClosed, color: '#ff6b6b' } : undefined,
    }));
    return { nodes, edges };
  }, [g, sel]);
  return (
    <div className="overflow-hidden rounded-2xl border border-line bg-surface" style={{ height }}>
      <ReactFlow key={g.nodes.length} nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.06, maxZoom: 1.1 }} minZoom={0.2} maxZoom={1.6}
        nodesConnectable={false} onNodeClick={(_, n) => onSelect(n.id)} proOptions={{ hideAttribution: true }}>
        <Background gap={22} size={1} color="#14291f" />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>
    </div>
  );
}

export function GraphLegend() {
  return (
    <div className="flex flex-wrap gap-x-5 gap-y-1.5 px-1 pt-3 text-[13px] text-sub">
      {Object.entries(KIND_NAME).map(([k, l]) => { const I = KIND_ICON[k]; return <span key={k} className="inline-flex items-center gap-1.5"><I size={14} style={{ color: KIND_COL[k] }} />{l}</span>; })}
      <span className="inline-flex items-center gap-1.5"><span className="h-3 w-3 rounded-sm border-2 border-danger" />Known to be malicious</span>
      <span className="font-medium text-danger">Dashed red line: the attack path</span>
    </div>
  );
}
