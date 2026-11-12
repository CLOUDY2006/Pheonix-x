import { AnimatePresence, motion } from 'framer-motion';
import { MessageCircle, Send, X } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api } from '../lib/api';
import { cx } from './ui';

interface Choice { label: string; send: string }
interface Msg { who: 'me' | 'ai'; text: string; choices?: (Choice | string)[] }
const STARTERS = ['status', 'brief me', "what's blocked"];

export function Assistant() {
  const [open, setOpen] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([{ who: 'ai', text: 'Hi. Ask me what is going on, or type “brief me”.' }]);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ behavior: 'smooth' }); }, [msgs, open]);
  const send = async (t: string) => {
    if (!t.trim() || busy) return;
    setMsgs((m) => [...m, { who: 'me', text: t }]); setText(''); setBusy(true);
    try { const r = await api('/api/chat', 'POST', { message: t }); setMsgs((m) => [...m, { who: 'ai', text: r.reply, choices: r.choices }]); }
    catch (e) { setMsgs((m) => [...m, { who: 'ai', text: (e as Error).message }]); }
    setBusy(false);
  };
  const submit = (e: FormEvent) => { e.preventDefault(); send(text); };
  return (
    <>
      <motion.button whileHover={{ y: -2 }} whileTap={{ scale: 0.95 }} onClick={() => setOpen(!open)} aria-label={open ? 'Close assistant' : 'Ask Phoenix X'} className="fixed bottom-24 right-5 z-40 grid h-14 w-14 place-items-center rounded-full bg-gradient-to-br from-[#ff7a45] to-[#ff4d5e] text-onink shadow-lift lg:bottom-6">{open ? <X size={22} /> : <MessageCircle size={22} />}</motion.button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, y: 20, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 20 }} transition={{ type: 'spring', stiffness: 320, damping: 28 }} className="fixed bottom-40 right-5 z-40 flex h-[460px] max-h-[70vh] w-[360px] max-w-[calc(100vw-40px)] flex-col overflow-hidden rounded-3xl border border-line bg-surface shadow-lift lg:bottom-24" role="dialog" aria-label="Ask Phoenix X">
            <div className="border-b border-line px-5 py-3.5"><b className="font-display text-[17px]">Ask Phoenix X</b><div className="text-[12.5px] text-mute">Plain-English questions about your security</div></div>
            <div className="flex-1 space-y-3 overflow-y-auto p-4">
              {msgs.map((m, i) => (
                <div key={i} className={cx('max-w-[88%] whitespace-pre-wrap rounded-2xl px-3.5 py-2.5 text-[14px]', m.who === 'me' ? 'ml-auto bg-ink text-onink' : 'bg-surface-2')}>
                  {m.text}
                  {m.choices && <div className="mt-2 flex flex-wrap gap-1.5">{m.choices.map((c) => { const ch = typeof c === 'string' ? { label: c, send: c } : c; return <button key={ch.label} onClick={() => send(ch.send)} className="rounded-full border border-[#2a4a3b] px-3 py-1 text-[12.5px] hover:border-calm">{ch.label}</button>; })}</div>}
                </div>
              ))}
              {busy && <div className="text-[13px] text-mute">Thinking</div>}
              <div ref={end} />
            </div>
            <div className="flex flex-wrap gap-1.5 px-4 pb-2">{STARTERS.map((q) => <button key={q} onClick={() => send(q)} className="rounded-full border border-line px-3 py-1 text-[12.5px] text-sub hover:border-calm hover:text-text">{q}</button>)}</div>
            <form onSubmit={submit} className="flex gap-2 border-t border-line p-3"><input aria-label="Message" className="field flex-1" placeholder="Ask something" value={text} onChange={(e) => setText(e.target.value)} /><button aria-label="Send" className="grid h-11 w-11 place-items-center rounded-xl bg-ink text-onink"><Send size={18} /></button></form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
