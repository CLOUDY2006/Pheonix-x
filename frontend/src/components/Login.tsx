import { motion } from 'framer-motion';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { api } from '../lib/api';
import { PHASES } from '../lib/format';
import { useApp } from '../lib/store';
import { Logo } from './Layout';
import { Btn } from './ui';

function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="grid min-h-screen bg-canvas lg:grid-cols-[1.1fr_1fr]">
      <div className="relative hidden flex-col justify-between border-r border-line p-12 lg:flex">
        <div className="flex items-center gap-3"><Logo size={42} /><span className="font-display text-[22px] font-bold">Phoenix X</span></div>
        <div>
          <div className="eyebrow">Autonomous security operations</div>
          <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7 }} className="mt-5 font-display text-[56px] font-bold leading-[1.02]">Security that<br /><span className="acc text-[62px]">shows its work.</span></motion.h1>
          <ul className="mt-9 space-y-4">
            {PHASES.map((ph, i) => (
              <motion.li key={ph.name} initial={{ opacity: 0, x: -18 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 + i * 0.15, duration: 0.5 }} className="flex items-center gap-4">
                <span className="grid h-10 w-10 place-items-center rounded-2xl border border-[#2a4a3b] font-display text-[17px] font-bold text-calm">{i + 1}</span>
                <div><div className="font-display text-[19px] font-bold leading-tight">{ph.name}</div><div className="text-[14px] text-mute">{ph.cap}</div></div>
              </motion.li>
            ))}
          </ul>
        </div>
        <p className="max-w-[46ch] text-[13.5px] text-mute">Every action Phoenix X takes is explained and written to a tamper-proof audit log.</p>
      </div>
      <div className="grid place-items-center p-6">
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} className="w-full max-w-[400px] rounded-[30px] border border-line bg-surface p-8 shadow-lift">
          <div className="mb-5 lg:hidden"><Logo size={46} /></div>
          {children}
        </motion.div>
      </div>
    </div>
  );
}
const Label = ({ id, children }: { id: string; children: ReactNode }) => <label htmlFor={id} className="mb-1.5 mt-4 block text-[13.5px] font-semibold text-sub">{children}</label>;

function SignIn() {
  const { login, setup, status } = useApp();
  const first = !!status?.setupRequired;
  const [u, setU] = useState(first ? '' : 'admin');
  const [p, setP] = useState('');
  const [t, setT] = useState('');
  const [tok, setTok] = useState('');
  const [needTotp, setNeedTotp] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (status?.demo && status.password && !first) setP(status.password); }, [status, first]);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr('');
    try { first ? await setup(u, p, tok || undefined) : await login(u, p, t || undefined); }
    catch (x) { const er = x as Error & { data?: { totpRequired?: boolean } }; if (er.data?.totpRequired) setNeedTotp(true); setErr(er.message); setBusy(false); }
  };
  return (
    <form onSubmit={submit}>
      <h1 className="mb-1">{first ? 'Create your admin account' : 'Welcome back'}</h1>
      <p className="mb-2 text-sub">{first ? 'This is the first run. The account you create here becomes the administrator.' : 'Sign in to see how your systems are doing.'}</p>
      <Label id="u">Username</Label><input id="u" className="field w-full" value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" />
      <Label id="p">{first ? 'Password (12 characters or more)' : 'Password'}</Label><input id="p" type="password" className="field w-full" value={p} onChange={(e) => setP(e.target.value)} autoComplete={first ? 'new-password' : 'current-password'} />
      {first && status?.setupTokenRequired && <><Label id="tok">Setup token (from the server log)</Label><input id="tok" className="field w-full" value={tok} onChange={(e) => setTok(e.target.value)} /></>}
      {needTotp && <><Label id="t">Authenticator code</Label><input id="t" inputMode="numeric" autoFocus className="field w-full" value={t} onChange={(e) => setT(e.target.value)} /></>}
      <Btn v="ember" size="lg" className="mt-6 w-full" disabled={busy}>{busy ? 'One moment' : first ? 'Create account' : 'Sign in'}</Btn>
      <p role="alert" className="mt-3 min-h-[22px] text-[14px] font-medium text-danger">{err}</p>
      {status?.demo && !first && <p className="rounded-2xl bg-surface-2 p-3.5 text-[13.5px] text-sub">Demo mode. <b>admin</b> can approve actions, <b>analyst</b> can investigate and run demos, <b>viewer</b> can only look.</p>}
    </form>
  );
}

function Enrol() {
  const { finishGate, logout } = useApp();
  const [d, setD] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [err, setErr] = useState('');
  useEffect(() => { api('/api/auth/totp/begin', 'POST', {}).then(setD).catch((e) => setErr(e.message)); }, []);
  const go = async (e: FormEvent) => { e.preventDefault(); try { await api('/api/auth/totp/confirm', 'POST', { code }); await finishGate(); } catch (x) { setErr((x as Error).message); } };
  return (
    <form onSubmit={go}>
      <h1 className="mb-1">Set up two-factor sign-in</h1>
      <p className="mb-3 text-sub">Add this key to an authenticator app (Google Authenticator, 1Password, Authy), then enter the 6-digit code.</p>
      {d && <div className="rounded-2xl bg-surface-2 p-4"><div className="text-[12.5px] text-mute">Secret key</div><div className="break-all font-mono text-[15px] text-calm">{d.secret}</div><a className="link mt-2 inline-block text-[13px]" href={d.uri}>Open in authenticator app</a></div>}
      <Label id="c">6-digit code</Label><input id="c" inputMode="numeric" className="field w-full" value={code} onChange={(e) => setCode(e.target.value)} />
      <Btn v="ember" size="lg" className="mt-6 w-full">Turn on two-factor</Btn>
      <button type="button" onClick={logout} className="mt-3 w-full text-center text-[13.5px] text-mute hover:text-text">Sign out</button>
      <p role="alert" className="mt-2 min-h-[22px] text-[14px] font-medium text-danger">{err}</p>
    </form>
  );
}

function ChangePassword() {
  const { finishGate, logout } = useApp();
  const [cur, setCur] = useState(''), [next, setNext] = useState(''), [err, setErr] = useState('');
  const go = async (e: FormEvent) => { e.preventDefault(); try { await api('/api/auth/password', 'POST', { current: cur, next }); await finishGate(); } catch (x) { setErr((x as Error).message); } };
  return (
    <form onSubmit={go}>
      <h1 className="mb-1">Choose a new password</h1>
      <p className="mb-2 text-sub">Your administrator asked you to change your password before continuing.</p>
      <Label id="cur">Current password</Label><input id="cur" type="password" className="field w-full" value={cur} onChange={(e) => setCur(e.target.value)} />
      <Label id="nx">New password (12 characters or more)</Label><input id="nx" type="password" className="field w-full" value={next} onChange={(e) => setNext(e.target.value)} />
      <Btn v="ember" size="lg" className="mt-6 w-full">Save and continue</Btn>
      <button type="button" onClick={logout} className="mt-3 w-full text-center text-[13.5px] text-mute hover:text-text">Sign out</button>
      <p role="alert" className="mt-2 min-h-[22px] text-[14px] font-medium text-danger">{err}</p>
    </form>
  );
}

export function Login({ gate }: { gate: 'enrol' | 'password' | null }) {
  return <Shell>{gate === 'enrol' ? <Enrol /> : gate === 'password' ? <ChangePassword /> : <SignIn />}</Shell>;
}
