'use strict';
// Optional write-through mirror to Supabase (PostgREST). Local memory stays the source of truth for the demo.
// "connected" is reported ONLY after a 2xx response from Supabase.
const st = { configured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY), ok: 0, failed: 0, lastError: null, lastOkAt: null };
async function upsert(table, id, row) {
  if (!st.configured) return;
  try {
    const r = await fetch(`${process.env.SUPABASE_URL}/rest/v1/${table}`, { method: 'POST', headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: 'Bearer ' + process.env.SUPABASE_SERVICE_ROLE_KEY, 'content-type': 'application/json', Prefer: 'resolution=merge-duplicates' }, body: JSON.stringify({ id, data: row, updated_at: new Date().toISOString() }), signal: AbortSignal.timeout(6000) });
    if (r.ok) { st.ok++; st.lastOkAt = new Date().toISOString(); } else { st.failed++; st.lastError = `HTTP ${r.status}`; }
  } catch (e) { st.failed++; st.lastError = e.message; }
}
const status = () => (!st.configured ? 'not configured (local memory store)' : st.ok > 0 ? `connected (${st.ok} writes confirmed)` : st.failed > 0 ? `error: ${st.lastError}` : 'configured, no writes yet');
module.exports = { upsert, status, st };
