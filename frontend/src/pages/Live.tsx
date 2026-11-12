import { useState } from 'react';
import { EventFeed } from '../components/shared';
import { Chip, PageHead, Panel, Toggle } from '../components/ui';
import { SRC } from '../lib/format';
import { useApp } from '../lib/store';

export function Live() {
  const { s } = useApp();
  const [filter, setFilter] = useState('all');
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState(s.events);
  const cnt = s.analytics.bySource || {};
  const base = paused ? frozen : s.events;
  const list = base.filter((e) => filter === 'all' || e.source === filter || e.origin === filter);
  return (
    <div>
      <PageHead title="Live activity" sub="Every event Phoenix X checks, as it happens. Red rows are part of a test attack." />
      <div className="mb-4 flex flex-wrap gap-2">{Object.keys(SRC).map((k) => <Chip key={k}>{SRC[k]} {cnt[k] || 0}</Chip>)}</div>
      <Panel className="p-0">
        <div className="flex flex-wrap items-center gap-4 border-b border-line px-5 py-3">
          <label className="flex items-center gap-2 text-[14px] text-sub">Show
            <select className="field py-1.5" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="all">Everything</option><option value="generated">Simulated background traffic</option><option value="scenario">Test attacks</option><option value="ingested">Real data you sent in</option>
              {Object.entries(SRC).map(([k, l]) => <option key={k} value={k}>{l} only</option>)}
            </select>
          </label>
          <label className="flex items-center gap-2 text-[14px] text-sub"><Toggle label="Pause" checked={paused} onChange={(v) => { setFrozen(s.events); setPaused(v); }} />Pause</label>
          <span className="ml-auto text-sub">{s.metrics.eventsToday || 0} events so far</span>
        </div>
        <EventFeed events={list} max={150} height={620} />
      </Panel>
    </div>
  );
}
