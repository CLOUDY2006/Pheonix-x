export interface ToastItem { id: number; msg: string; kind: 'ok' | 'bad' | 'info' }
type L = (t: ToastItem) => void;
const listeners = new Set<L>();
let n = 0;
export const onToast = (l: L) => { listeners.add(l); return () => { listeners.delete(l); }; };
export const toast = (msg: string, kind: ToastItem['kind'] = 'info') => { const t = { id: ++n, msg, kind }; listeners.forEach((l) => l(t)); };
