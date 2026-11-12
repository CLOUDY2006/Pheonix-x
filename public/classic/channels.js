'use strict';
// Chat & Alerts page: Telegram / Slack / Discord / email. Loaded after pages.js.
ICONS.chan = 'M4 5h16v11H9l-5 4zM8 9h8M8 12h5';
PAGES.splice(PAGES.findIndex((p) => p[0] === 'connect') + 1, 0, ['channels', 'Chat & Alerts', 'chan']);
const CH = { data: null, kind: 'telegram', pair: {}, loaded: false };
async function chLoad() { try { CH.data = await api('/api/channels'); } catch (e) { toast(e.message, 'bad'); } CH.loaded = true; later(30); }
PAGE_FN.channels = () => {
  if (!isAdmin()) return '<h1>Chat & Alerts</h1><p class="sub">Only administrators can manage chat channels.</p>';
  if (!CH.loaded) { CH.loaded = true; chLoad(); } const D = CH.data; if (!D) return '<h1>Chat & Alerts</h1><div class="note">Loading…</div>';
  const spec = D.catalog[CH.kind], origin = location.origin;
  const card = (c) => `<div class="card" style="margin-bottom:12px"><div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:8px"><div><b>${esc(c.name)}</b> <span class="chip">${esc(c.spec)}</span> ${c.enabled ? (c.status === 'ok' ? '<span class="st-ok">● connected</span>' : c.status === 'pending' ? '<span class="mut">● waiting</span>' : `<span class="st-bad">● ${esc(c.status)}</span>`) : '<span class="mut">● paused</span>'}${c.error ? `<div class="mut" style="font-size:11px">${esc(c.error)}</div>` : ''}</div>
  <div class="row" style="gap:6px;flex-wrap:wrap"><button class="btn sm" data-ch="test" data-id="${esc(c.id)}">Send test</button>${D.catalog[c.kind].inbound ? `<button class="btn pri sm" data-ch="pair" data-id="${esc(c.id)}">Pair a person</button>` : ''}<button class="btn sm" data-ch="pause" data-id="${esc(c.id)}" data-on="${c.enabled ? '' : '1'}">${c.enabled ? 'Pause' : 'Resume'}</button><button class="btn sm" data-ch="del" data-id="${esc(c.id)}">Remove</button></div></div>
  ${CH.pair[c.id] ? `<div class="note" style="margin-top:8px"><b>Send this to ${esc(c.spec)} within 15 minutes:</b> <span class="mono" style="user-select:all;font-size:15px">link ${esc(CH.pair[c.id].code)}</span><div class="mut">${c.kind === 'telegram' ? 'Open a private chat with your bot and send it.' : c.kind === 'slack' ? 'Run it as: /phoenix link CODE' : 'Run it as: /phoenix text:link CODE'} This code works once.</div></div>` : ''}
  ${c.inboundUrl ? `<div class="mut" style="margin-top:6px">${c.kind === 'slack' ? 'Slash command Request URL' : 'Interactions Endpoint URL'}: <span class="mono" style="user-select:all">${esc((D.publicUrl || origin) + c.inboundUrl)}</span> <span class="mut">(must be public https)</span></div>` : ''}
  <div class="row" style="gap:10px;flex-wrap:wrap;margin-top:8px;align-items:center"><span class="mut">Alert me for</span><select data-ch="sev" data-id="${esc(c.id)}">${['low', 'medium', 'high', 'critical'].map((s) => `<option ${c.minSeverity === s ? 'selected' : ''}>${s}</option>`).join('')}</select><span class="mut">and above · commands as</span><select data-ch="role" data-id="${esc(c.id)}">${['analyst', 'viewer'].map((s) => `<option ${c.role === s ? 'selected' : ''}>${s}</option>`).join('')}</select>${D.catalog[c.kind].inbound ? `<span class="mut">· ${c.allow.length} paired</span>${c.allow.map((a) => `<span class="chip">${esc(a)} <a data-ch="unallow" data-id="${esc(c.id)}" data-u="${esc(a)}" style="cursor:pointer">✕</a></span>`).join('')}` : ''}</div></div>`;
  return `<h1>Chat & Alerts</h1><p class="sub">Get alerts, and give commands from Telegram, Slack or Discord ("block 203.0.113.9", "status", "brief me"). Anything that needs a human decision (Allow/Disallow, key rotation, mode changes) stays in this app.</p>
  ${D.channels.map(card).join('') || '<div class="note">No channels yet. Add one below.</div>'}
  <div class="card"><h2>Add a channel</h2><div class="tabs">${Object.entries(D.catalog).map(([k, v]) => `<a data-ch="kind" data-id="${k}" class="${CH.kind === k ? 'on' : ''}">${esc(v.label)}</a>`).join('')}</div><p class="mut">${esc(spec.help)}</p>
  <form data-chf="new" class="row" style="gap:8px;flex-wrap:wrap"><input name="name" placeholder="Name (optional)">${spec.fields.map((f) => `<input name="${f.k}" placeholder="${esc(f.label)}${f.optional ? ' (optional)' : ''}" ${f.optional ? '' : 'required'} ${f.secret ? 'type="password" autocomplete="off"' : ''} style="min-width:240px">`).join('')}<select name="minSeverity"><option>high</option><option>critical</option><option>medium</option><option>low</option></select><button class="btn pri sm">Connect</button></form><div id="chmsg"></div>
  <p class="mut">Secrets are stored encrypted and never shown again. People must be <b>paired</b> before the bot obeys them. Chat users are capped at analyst rights.</p></div>`;
};
document.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-ch]'); if (!el) return; const a = el.dataset.ch, id = el.dataset.id;
  if (a === 'kind') { CH.kind = id; return render(); }
  if (a === 'pair') { const r = await act(() => api(`/api/channels/${id}/pair`, 'POST', {})); if (r) { CH.pair[id] = r; render(); } return; }
  if (a === 'test') { const r = await act(() => api(`/api/channels/${id}/test`, 'POST', {})); if (r) toast('Test sent to ' + r.to, 'ok'); return chLoad(); }
  if (a === 'pause') { await act(() => api(`/api/channels/${id}/enable`, 'POST', { enabled: !!el.dataset.on })); return chLoad(); }
  if (a === 'del') { if (confirm('Remove this channel?')) { await act(() => api(`/api/channels/${id}/remove`, 'POST', {}), 'Removed'); return chLoad(); } return; }
  if (a === 'unallow') { await act(() => api(`/api/channels/${id}/allow`, 'POST', { user: el.dataset.u, on: false }), 'Removed'); return chLoad(); }
});
document.addEventListener('change', async (ev) => {
  const el = ev.target.closest('select[data-ch]'); if (!el) return; const body = el.dataset.ch === 'sev' ? { minSeverity: el.value } : { role: el.value };
  await act(() => api(`/api/channels/${el.dataset.id}/settings`, 'POST', body), 'Saved'); chLoad();
});
document.addEventListener('submit', async (ev) => {
  if (ev.target.dataset?.chf !== 'new') return; ev.preventDefault(); const d = Object.fromEntries(new FormData(ev.target)), { name, minSeverity, ...config } = d;
  $('#chmsg').innerHTML = '<div class="note">Checking the connection…</div>';
  try { const r = await api('/api/channels', 'POST', { kind: CH.kind, name, minSeverity, config }); ev.target.reset(); $('#chmsg').innerHTML = ''; toast('Connected. Press "Pair a person" next.', 'ok'); await chLoad(); if (r.id) { CH.pair[r.id] = null; } } catch (e) { $('#chmsg').innerHTML = `<div class="note" style="border-color:#ff5a5f">${esc(e.message)}</div>`; }
});
