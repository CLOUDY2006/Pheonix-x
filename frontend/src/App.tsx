import { Login } from './components/Login';
import { Shell } from './components/Layout';
import { Toasts } from './components/Toasts';
import { Assistant } from './components/Assistant';
import { useApp, useRoute } from './lib/store';
import { Overview } from './pages/Overview';
import { Live } from './pages/Live';
import { Incidents } from './pages/Incidents';
import { AttackMap } from './pages/AttackMap';
import { Response } from './pages/Response';
import { Recovery } from './pages/Recovery';
import { Agents } from './pages/Agents';
import { Intel } from './pages/Intel';
import { Assets } from './pages/Assets';
import { Trends } from './pages/Trends';
import { Audit } from './pages/Audit';
import { Settings } from './pages/Settings';
import { Approvals } from './pages/Approvals';
import { Activity } from './pages/Activity';
import { Advanced } from './pages/Advanced';

const PAGES: Record<string, (p: { arg?: string }) => JSX.Element> = {
  command: Overview, live: Live, incidents: Incidents, graph: AttackMap, response: Response, recovery: Recovery,
  advanced: Advanced, approvals: Approvals, activity: Activity, agents: Agents, intel: Intel, assets: Assets, analytics: Trends, audit: Audit, settings: Settings,
};

export function App() {
  const { me, gate, booting } = useApp();
  const { page, arg } = useRoute();
  const Page = PAGES[page] || Overview;
  return (
    <>
      {booting ? <div className="grid min-h-screen place-items-center text-mute">Loading</div> : me && !gate ? <Shell page={PAGES[page] ? page : 'command'}><Page arg={arg} /></Shell> : <Login gate={gate} />}
      {me && !gate && !booting && <Assistant />}
      <Toasts />
    </>
  );
}
