import { ArrowUpRight } from 'lucide-react';
import { PageHead, Panel, Rise, Stagger, Tile } from '../components/ui';
import { ScenarioList } from '../components/shared';
import { useApp } from '../lib/store';
import { ADV, CLASSIC } from '../lib/nav';

const TINT = ['bg-brand-soft text-brand', 'bg-calm-soft text-calm-dark', 'bg-ember-soft text-ember-dark', 'bg-warn-soft text-warn'];

export function Advanced() {
  const { s } = useApp();
  const demo = s.mode === 'demo' && s.scenarios.length > 0;
  return (
    <div>
      <PageHead title="More tools" sub="For experts who want to look under the hood. You never need these to stay safe, because Phoenix X handles it." />
      {demo && <Panel className="mb-8"><h2 className="mb-1">Practice attacks</h2><p className="mb-2 text-sub">Safe, fake attacks so you can watch Phoenix X respond. Pick any one.</p><ScenarioList list={s.scenarios} /></Panel>}
      <Stagger className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {ADV.map(([k, label, Icon, hint], i) => (
          <Rise key={k}>
            <a href={`#/${k}`} className="block h-full">
              <Tile className="group h-full cursor-pointer">
                <div className="mb-5 flex items-start justify-between"><span className={`grid h-12 w-12 place-items-center rounded-2xl ${TINT[i % 4]}`}><Icon size={22} /></span><ArrowUpRight size={20} className="text-[#b6bfcd] transition-all group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-text" /></div>
                <h2 className="mb-1">{label}</h2><p className="text-[14px] text-sub">{hint}</p>
              </Tile>
            </a>
          </Rise>
        ))}
      </Stagger>
      <h2 className="mb-3 mt-10">Set-up and admin</h2>
      <Stagger className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {CLASSIC.map((c) => (
          <Rise key={c.href}><a href={c.href} className="block h-full"><Tile className="group h-full cursor-pointer !p-5"><div className="mb-2 flex items-start justify-between"><b className="font-display text-[17px]">{c.label}</b><ArrowUpRight size={18} className="text-mute transition-all group-hover:text-text" /></div><p className="text-[13.5px] text-sub">{c.hint}</p></Tile></a></Rise>
        ))}
      </Stagger>
    </div>
  );
}
