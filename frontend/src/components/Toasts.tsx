import { AnimatePresence, motion } from 'framer-motion';
import { useEffect, useState } from 'react';
import { onToast, type ToastItem } from '../lib/toast';
import { cx } from './ui';

export function Toasts() {
  const [list, setList] = useState<ToastItem[]>([]);
  useEffect(() => onToast((t) => { setList((l) => [...l, t]); setTimeout(() => setList((l) => l.filter((x) => x.id !== t.id)), 5200); }), []);
  return (
    <div aria-live="polite" className="fixed bottom-5 right-5 z-50 flex flex-col gap-2">
      <AnimatePresence>
        {list.map((t) => (
          <motion.div key={t.id} layout initial={{ opacity: 0, x: 40 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 40 }} transition={{ type: 'spring', stiffness: 380, damping: 30 }}
            className={cx('max-w-[360px] rounded-xl border border-line border-l-4 bg-surface px-4 py-3 text-[14px] shadow-[0_10px_30px_-10px_rgba(11,18,34,.3)]', t.kind === 'ok' ? 'border-l-calm' : t.kind === 'bad' ? 'border-l-danger' : 'border-l-brand')}>
            {t.msg}
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
