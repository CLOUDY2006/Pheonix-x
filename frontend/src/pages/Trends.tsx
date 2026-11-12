import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Empty, PageHead, Panel } from '../components/ui';
import { AG_NAME, SRC } from '../lib/format';
import { useApp } from '../lib/store';
import type { Any } from '../types';

const toRows = (o: Record<string, number> = {}, map?: Record<string, string>) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => ({ name: map?.[k] || k, v }));
const PIE = ['#ff6b6b', '#ff6b35', '#ffc15a', '#7ea1ff', '#2ee6a6'];

function HBars({ data, color, w = 118 }: { data: { name: string; v: number }[]; color: string; w?: number }) {
  if (!data.length) return <Empty>Nothing to show yet</Empty>;
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 34)}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16, top: 4, bottom: 4 }}>
        <XAxis type="number" hide /><YAxis type="category" dataKey="name" width={w} tick={{ fontSize: 12.5, fill: '#b3cfc3' }} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: '#0c1f17' }} contentStyle={{ borderRadius: 10, border: '1px solid #14291f', fontSize: 13 }} /><Bar dataKey="v" name="Count" fill={color} radius={[0, 6, 6, 0]} barSize={16} isAnimationActive />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function Trends() {
  const { s } = useApp();
  const A = s.analytics as Any;
  const series = (A.series || []).map((p: Any, i: number) => ({ ...p, t: i }));
  const pri: Record<string, number> = {}; s.incidents.forEach((i) => (pri[i.priority] = (pri[i.priority] || 0) + 1));
  const pie = Object.entries(pri).map(([name, value]) => ({ name, value }));
  return (
    <div>
      <PageHead title="Trends" sub="How many events came in, what was caught and how fast Phoenix X responded." />
      <Panel className="mb-5"><h2 className="mb-3">Events in the last 10 minutes</h2>
        <div role="img" aria-label="Stacked bar chart of events over the last ten minutes"><ResponsiveContainer width="100%" height={220}>
          <BarChart data={series} margin={{ left: -18, right: 4, top: 4 }}><CartesianGrid vertical={false} stroke="#14291f" /><XAxis dataKey="t" hide /><YAxis tick={{ fontSize: 12, fill: '#8fb3a4' }} axisLine={false} tickLine={false} />
            <Tooltip cursor={{ fill: '#0c1f17' }} contentStyle={{ borderRadius: 10, border: '1px solid #14291f', fontSize: 13 }} labelFormatter={() => '30 second window'} /><Legend iconType="circle" wrapperStyle={{ fontSize: 13 }} />
            <Bar dataKey="generated" name="Simulated" stackId="a" fill="#9db3f2" /><Bar dataKey="scenario" name="Test attack" stackId="a" fill="#ff6b6b" /><Bar dataKey="ingested" name="Real data" stackId="a" fill="#2ee6a6" radius={[4, 4, 0, 0]} />
          </BarChart></ResponsiveContainer></div>
      </Panel>
      <div className="mb-5 grid gap-5 lg:grid-cols-3">
        <Panel><h2 className="mb-2">Where events came from</h2><HBars data={toRows(A.bySource, SRC)} color="#7ea1ff" /></Panel>
        <Panel><h2 className="mb-2">Types of alert</h2><HBars data={toRows(A.cats).map((r) => ({ ...r, name: r.name.replace(/_/g, ' ') }))} color="#ff6b35" /></Panel>
        <Panel><h2 className="mb-2">Detection rules that fired</h2><HBars data={toRows(A.rules).map((r) => ({ ...r, name: r.name.replace(/^R-/, '').replace(/-/g, ' ').toLowerCase().replace(/^./, (m) => m.toUpperCase()) }))} color="#7a4fe0" w={150} /></Panel>
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <Panel><h2 className="mb-2">Incidents by priority</h2>
          {pie.length ? <ResponsiveContainer width="100%" height={200}><PieChart><Pie data={pie} dataKey="value" nameKey="name" innerRadius={48} outerRadius={80} paddingAngle={3} stroke="none">{pie.map((_, i) => <Cell key={i} fill={PIE[i % PIE.length]} />)}</Pie><Tooltip contentStyle={{ borderRadius: 10, border: '1px solid #14291f', fontSize: 13 }} /><Legend iconType="circle" wrapperStyle={{ fontSize: 13 }} /></PieChart></ResponsiveContainer> : <Empty>No incidents yet</Empty>}
        </Panel>
        <Panel><h2 className="mb-2">Time to contain</h2>{(A.contain || []).map((c: Any) => <div key={c.id} className="my-2 flex justify-between"><span className="font-mono text-[12.5px]">{c.id}</span><b>{c.sec}s</b></div>)}{!(A.contain || []).length && <Empty>None yet</Empty>}<p className="mt-2 text-[13px] text-mute">From detection to the first action. Waiting for approval counts.</p></Panel>
        <Panel><h2 className="mb-2">Helper activity</h2>{Object.entries(s.agents).map(([k, a]) => <div key={k} className="my-2 flex justify-between"><b>{AG_NAME[k]}</b><span className="text-sub">{a.runs} runs, {a.failures} failed</span></div>)}</Panel>
      </div>
    </div>
  );
}
