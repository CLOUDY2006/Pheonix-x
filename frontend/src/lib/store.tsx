import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef, useState, type ReactNode } from 'react';
import type { Any, AppState, Me } from '../types';
import { api, setCsrf, setExpiredHandler } from './api';
import { toast } from './toast';

const empty: AppState = { metrics: {}, incidents: [], agents: {}, messages: [], scenarios: [], integrations: {}, settings: {}, approvals: [], events: [], assets: {}, analytics: { series: [] }, audit: [], autonomy: {}, connectors: {}, mode: 'demo' };
type Action = { t: string; d?: Any };

function reducer(s: AppState, a: Action): AppState {
  const d = a.d;
  switch (a.t) {
    case 'state': return { ...s, ...d };
    case 'event': return { ...s, events: [...s.events, d].slice(-300), metrics: { ...s.metrics, eventsToday: (s.metrics.eventsToday || 0) + 1 } };
    case 'incident': {
      const known = s.incidents.some((x) => x.id === d.id);
      const incidents = known ? s.incidents.map((x) => (x.id === d.id ? d : x)) : [d, ...s.incidents];
      return { ...s, incidents, approvals: s.approvals.filter((p) => p.incidentId !== d.id || d.pendingApprovals > 0) };
    }
    case 'agents': return { ...s, agents: d };
    case 'agent_msg': return { ...s, messages: [...s.messages, d].slice(-100) };
    case 'approval': return { ...s, approvals: [...s.approvals, d] };
    case 'metrics': return { ...s, metrics: { ...s.metrics, ...d }, assets: d.assets ?? s.assets, analytics: d.analytics ?? s.analytics, ops: d.ops ?? s.ops };
    case 'audit': return { ...s, audit: [...s.audit, d].slice(-1500) };
    case 'dropApproval': return { ...s, approvals: s.approvals.filter((p) => p.action.id !== d) };
    case 'settings': return { ...s, settings: d };
    case 'autonomy': return { ...s, autonomy: d, settings: { ...s.settings, autoContain: d.mode !== 'watch' } };
    default: return s;
  }
}

export interface AuthStatus { mode: string; setupRequired: boolean; setupTokenRequired: boolean; demo: boolean; password?: string; requireAdminTotp?: boolean }
export type Gate = null | 'enrol' | 'password';
interface Ctx {
  s: AppState; me: Me | null; live: boolean; narr: { text: string; ts: number } | null; booting: boolean; gate: Gate; status: AuthStatus | null;
  login: (u: string, p: string, totp?: string) => Promise<void>; setup: (u: string, p: string, token?: string) => Promise<void>; finishGate: () => Promise<void>;
  logout: () => void; dispatch: (a: Action) => void; reload: () => Promise<void>;
}
const C = createContext<Ctx>(null as unknown as Ctx);
export const useApp = () => useContext(C);
export const useCan = () => { const { me } = useApp(); return { admin: me?.role === 'admin', act: !!me && me.role !== 'viewer' }; };

export function Provider({ children }: { children: ReactNode }) {
  const [s, dispatch] = useReducer(reducer, empty);
  const [me, setMe] = useState<Me | null>(null);
  const [gate, setGate] = useState<Gate>(null);
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [booting, setBooting] = useState(true);
  const [live, setLive] = useState(false);
  const [narr, setNarr] = useState<Ctx['narr']>(null);
  const ws = useRef<WebSocket | null>(null);
  const timer = useRef<number>();
  const known = useRef<string[]>([]);
  const pendingToast = useRef(0);
  const pendingTimer = useRef<number>();
  known.current = s.incidents.map((i) => i.id);

  const reload = useCallback(async () => { const d = await api('/api/state'); dispatch({ t: 'state', d }); }, []);
  const applySession = useCallback((r: Any) => {
    setCsrf(r.csrf || null);
    setMe({ user: r.user, role: r.role });
    setGate(r.totpEnrolRequired ? 'enrol' : r.mustChange ? 'password' : null);
  }, []);
  const logout = useCallback(() => { api('/api/auth/logout', 'POST', {}).catch(() => {}); setCsrf(null); ws.current?.close(); setMe(null); setGate(null); api('/api/auth/status').then(setStatus).catch(() => {}); }, []);
  const login = useCallback(async (username: string, password: string, totp?: string) => { applySession(await api('/api/auth/login', 'POST', { username, password, ...(totp ? { totp } : {}) })); }, [applySession]);
  const setup = useCallback(async (username: string, password: string, setupToken?: string) => { applySession(await api('/api/auth/setup', 'POST', { username, password, ...(setupToken ? { setupToken } : {}) })); }, [applySession]);
  const finishGate = useCallback(async () => { applySession(await api('/api/auth/me')); }, [applySession]);
  useEffect(() => { setExpiredHandler(() => { setMe(null); setCsrf(null); }); }, []);

  useEffect(() => {
    let dead = false;
    (async () => {
      try { const st = await api('/api/auth/status'); if (!dead) setStatus(st); } catch { /* offline */ }
      try { const r = await api('/api/auth/me'); if (!dead) applySession(r); } catch { /* not signed in */ }
      if (!dead) setBooting(false);
    })();
    return () => { dead = true; };
  }, [applySession]);

  useEffect(() => {
    if (!me || gate) return;
    let dead = false;
    reload().then(() => api('/api/audit?limit=500')).then((a) => dispatch({ t: 'state', d: { audit: a } })).catch(() => {});
    const connect = () => {
      if (dead) return;
      const w = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
      ws.current = w;
      w.onopen = () => setLive(true);
      w.onclose = () => { setLive(false); if (!dead) timer.current = window.setTimeout(connect, 2000); };
      w.onmessage = (m) => {
        try {
          const { type, data } = JSON.parse(m.data);
          if (type === 'incident' && !known.current.includes(data.id)) toast(`New incident ${data.id}: ${data.title}`, 'info');
          if (type === 'approval') { pendingToast.current += 1; clearTimeout(pendingTimer.current); pendingTimer.current = window.setTimeout(() => { const n = pendingToast.current; pendingToast.current = 0; toast(n === 1 ? `Your decision is needed: ${data.action.description}` : `${n} decisions are waiting for you`, 'info'); }, 900); }
          if (type === 'scenario') setNarr({ text: data.step === 'DONE' ? 'The test events are in. The AI helpers are now working on it.' : data.step === 'START' ? 'Starting the simulated attack' : data.step, ts: Date.now() });
          if (type === 'reset') reload();
          else dispatch({ t: type, d: data });
        } catch (e) { console.error(e); }
      };
    };
    connect();
    return () => { dead = true; clearTimeout(timer.current); ws.current?.close(); };
  }, [me, gate, reload]);

  useEffect(() => { if (!narr) return; const i = setTimeout(() => setNarr(null), 10000); return () => clearTimeout(i); }, [narr]);

  const v = useMemo(() => ({ s, me, live, narr, booting, gate, status, login, setup, finishGate, logout, dispatch, reload }), [s, me, live, narr, booting, gate, status, login, setup, finishGate, logout, reload]);
  return <C.Provider value={v}>{children}</C.Provider>;
}

const stampOf = (i: { state: string; actions: number; tasks: { done: number; total: number }; pendingApprovals: number; alerts: number; status: string }) => [i.state, i.actions, i.tasks.done, i.tasks.total, i.pendingApprovals, i.alerts, i.status].join('|');

export function useIncident(id?: string | null) {
  const { s } = useApp();
  const [d, setD] = useState<Any>(null);
  const sum = s.incidents.find((i) => i.id === id);
  const stamp = sum ? stampOf(sum) : '';
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!id) { setD(null); return; }
    let dead = false;
    const t = setTimeout(() => { api('/api/incidents/' + id).then((r) => { if (!dead) setD(r); }).catch(() => {}); }, 200);
    return () => { dead = true; clearTimeout(t); };
  }, [id, stamp, tick]);
  return { d: d && d.id === id ? d : null, refresh: () => setTick((x) => x + 1) };
}

export function useAllDetails() {
  const { s } = useApp();
  const [map, setMap] = useState<Record<string, Any>>({});
  const stamps = useRef<Record<string, string>>({});
  useEffect(() => {
    for (const i of s.incidents) {
      const st = stampOf(i);
      if (stamps.current[i.id] !== st) { stamps.current[i.id] = st; api('/api/incidents/' + i.id).then((r) => setMap((m) => ({ ...m, [i.id]: r }))).catch(() => {}); }
    }
  }, [s.incidents]);
  return s.incidents.map((i) => map[i.id]).filter(Boolean);
}

export function useRoute() {
  const parse = () => { const h = (location.hash || '#/command').slice(2).split('/'); return { page: h[0] || 'command', arg: h[1] }; };
  const [r, setR] = useState(parse);
  useEffect(() => { const f = () => { setR(parse()); document.getElementById('main')?.scrollTo(0, 0); }; window.addEventListener('hashchange', f); return () => window.removeEventListener('hashchange', f); }, []);
  return r;
}
export const go = (h: string) => { location.hash = h; };

export function useCount(target: number, ms = 700) {
  const [v, setV] = useState(target);
  const from = useRef(target);
  useEffect(() => {
    const start = performance.now(), a = from.current, reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce || a === target) { setV(target); from.current = target; return; }
    let raf = 0;
    const tick = (now: number) => { const p = Math.min(1, (now - start) / ms), e = 1 - Math.pow(1 - p, 3); setV(Math.round(a + (target - a) * e)); if (p < 1) raf = requestAnimationFrame(tick); else from.current = target; };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}
