import { Background, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from '@xyflow/react';
import { Bot, Eye, Search, ShieldCheck, LifeBuoy, Radar, type LucideIcon } from 'lucide-react';
import { useMemo } from 'react';
import type { Any } from '../types';
import { AG_COL, AG_NAME } from '../lib/format';
import { cx } from './ui';

const ICON: Record<string, LucideIcon> = { SENTINEL: Radar, INVESTIGATOR: Search, ORACLE: Eye, GUARDIAN: ShieldCheck, RECOVERY: LifeBuoy, COMMANDER: Bot };
const POS: Record<string, [number, number]> = { SENTINEL: [0, 130], COMMANDER: [340, 130], INVESTIGATOR: [700, -10], ORACLE: [700, 90], GUARDIAN: [700, 190], RECOVERY: [700, 290] };

function AgentNode({ data }: NodeProps) {
  const d = data as Any; const Icon = ICON[d.k]; const working = d.state === 'working';
  return (
    <div className={cx('flex w-[250px] items-center gap-3 rounded-2xl border bg-surface p-3 transition-shadow', working ? 'border-ember shadow-[0_0_0_5px_rgba(255,107,53,.15)]' : 'border-line')}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} isConnectable={false} /><Handle type="source" position={Position.Right} style={{ opacity: 0 }} isConnectable={false} />
      <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl text-white" style={{ background: AG_COL[d.k] }}><Icon size={19} /></div>
      <div className="min-w-0"><div className="text-[14.5px] font-semibold leading-tight">{AG_NAME[d.k]}</div><div className="truncate text-[12.5px] text-mute">{working ? d.current || 'Working' : d.role}</div></div>
    </div>
  );
}
const nodeTypes = { agent: AgentNode };

export function AgentFlow({ agents, roles, height = 400 }: { agents: Record<string, Any>; roles: Record<string, string>; height?: number }) {
  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = Object.keys(POS).map((k) => ({ id: k, type: 'agent', position: { x: POS[k][0], y: POS[k][1] }, data: { k, role: roles[k], state: agents[k]?.state, current: agents[k]?.current }, draggable: false }));
    const pairs: [string, string][] = [['SENTINEL', 'COMMANDER'], ['COMMANDER', 'INVESTIGATOR'], ['COMMANDER', 'ORACLE'], ['COMMANDER', 'GUARDIAN'], ['COMMANDER', 'RECOVERY']];
    const edges: Edge[] = pairs.map(([a, b]) => { const hot = agents[a]?.state === 'working' || agents[b]?.state === 'working'; return { id: a + b, source: a, target: b, animated: hot, style: { stroke: hot ? '#ff6b35' : '#2f5a47', strokeWidth: hot ? 2.4 : 1.6 }, markerEnd: { type: MarkerType.ArrowClosed, color: hot ? '#ff6b35' : '#2f5a47' } }; });
    return { nodes, edges };
  }, [agents, roles]);
  return (
    <div className="overflow-hidden rounded-2xl border border-line bg-surface" style={{ height }}>
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.08 }} nodesDraggable={false} nodesConnectable={false} panOnDrag={false} zoomOnScroll={false} zoomOnPinch={false} zoomOnDoubleClick={false} preventScrolling={false} proOptions={{ hideAttribution: true }}>
        <Background gap={22} size={1} color="#14291f" />
      </ReactFlow>
    </div>
  );
}
