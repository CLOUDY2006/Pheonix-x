import type { Any } from '../types';

let csrf: string | null = null;
export const setCsrf = (c: string | null) => { csrf = c; };
let onExpired: () => void = () => {};
export const setExpiredHandler = (fn: () => void) => { onExpired = fn; };

export async function api<T = Any>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const r = await fetch(path, { method, credentials: 'same-origin', headers: { 'content-type': 'application/json', ...(csrf && method !== 'GET' ? { 'x-csrf-token': csrf } : {}) }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401 && !path.includes('/auth/')) { onExpired(); throw new Error('Your session expired. Please sign in again.'); }
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) { const err = new Error((data as Any).error || r.statusText) as Error & { data?: Any; status?: number }; err.data = data; err.status = r.status; throw err; }
  return data as T;
}

export async function download(path: string, name: string) {
  const r = await fetch(path, { credentials: 'same-origin' });
  if (!r.ok) throw new Error((await r.json()).error);
  const a = document.createElement('a'); a.href = URL.createObjectURL(await r.blob()); a.download = name; a.click();
}
