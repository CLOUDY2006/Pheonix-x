'use strict';
// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtT = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false });
const fmtDT = (ts) => new Date(ts).toLocaleString([], { hour12: false });
const sevChip = (s) => `<span class="chip sev-${esc(s)}">${esc(s)}</span>`;
const tierChip = (t) => `<span class="chip t-${esc(t)}">${t === 'approval' ? 'approval required' : esc(t)}</span>`;
const originChip = (o) => (o === 'ingested' ? '<span class="chip live">LIVE</span>' : o === 'scenario' ? '<span class="chip atk">ATTACK SIM</span>' : '<span class="chip sim">SIM</span>');
const AGENT_COL = { SENTINEL: '#ff8a96', INVESTIGATOR: '#38d6ff', ORACLE: '#a78bfa', GUARDIAN: '#3ddc97', RECOVERY: '#ffd24a', COMMANDER: '#ffb347' };
const ICONS = { conn: 'M9 3v5M15 3v5M6 8h12v4a6 6 0 01-12 0zM12 18v3', cmd: 'M3 12l9-8 9 8M5 10v10h14V10', live: 'M3 12h4l3-8 4 16 3-8h4', agents: 'M12 8a4 4 0 100 .01M4 21c0-4 3.5-7 8-7s8 3 8 7', inc: 'M12 3l10 18H2zM12 10v5M12 18v.01', graph: 'M6 6a2 2 0 100 .01M18 6a2 2 0 100 .01M12 18a2 2 0 100 .01M7.5 7.5l3 8M16.5 7.5l-3 8M8 6h8', intel: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18', resp: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4', rec: 'M4 12a8 8 0 108-8M4 4v5h5', assets: 'M3 5h18v6H3zM3 13h18v6H3zM7 8v.01M7 16v.01', ana: 'M4 20V10M10 20V4M16 20v-8M22 20H2', audit: 'M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7', set: 'M12 9a3 3 0 100 6 3 3 0 000-6zM19 12l2-1-2-4-2 1-2-1V5h-4v2l-2 1-2-1-2 4 2 1v2l-2 1 2 4 2-1 2 1v2h4v-2l2-1 2 1 2-4-2-1z' };
const PAGES = [['command', 'Security Command Centre', 'cmd'], ['live', 'Live Threat Monitor', 'live'], ['agents', 'AI Agent Operations', 'agents'], ['incidents', 'Incident Investigation', 'inc'], ['graph', 'Attack Graph', 'graph'], ['intel', 'Threat Intelligence', 'intel'], ['response', 'Automated Response', 'resp'], ['recovery', 'Recovery Centre', 'rec'], ['assets', 'Asset Inventory', 'assets'], ['connect', 'Connect a Platform', 'conn'], ['analytics', 'Security Analytics', 'ana'], ['audit', 'Audit Logs', 'audit'], ['settings', 'Settings', 'set']];

// ---------- state ----------
let ME = null, CSRF = null; // the session itself lives in an HttpOnly cookie that scripts cannot read
const S = { metrics: {}, incidents: [], agents: {}, messages: [], scenarios: [], integrations: {}, settings: {}, approvals: [], events: [], assets: {}, analytics: { series: [] }, audit: [], notifications: [] };
const U = { detail: null, detailId: null, tab: 'overview', graphInc: null, node: null, feedFilter: 'all', feedPaused: false, narr: null, auditFilter: '' };
const isAdmin = () => ME?.role === 'admin', canAct = () => ME && ME.role !== 'viewer';

async function api(path, method = 'GET', body) {
  const r = await fetch(path, { method, headers: { 'content-type': 'application/json', ...(CSRF && method !== 'GET' ? { 'x-csrf-token': CSRF } : {}) }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401 && !path.includes('/auth/')) { showLogin(); throw new Error('session expired'); }
  const ct = r.headers.get('content-type') || ''; const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error(data.error || r.statusText); return data;
}
const act = async (fn, ok) => { try { const r = await fn(); if (ok) toast(ok, 'ok'); return r; } catch (e) { toast(e.message, 'bad'); } };
function toast(msg, kind = '') { const t = document.createElement('div'); t.className = 'toast ' + kind; t.innerHTML = msg; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 5200); }

// ---------- login / first-run setup ----------
const LOGO = '<svg viewBox="0 0 32 32" width="46" height="46" style="display:block;margin:0 auto"><path d="M16 2c2 6 8 8 8 15a8 8 0 0 1-16 0c0-3 1-5 3-7 0 3 2 4 3 4-2-5 0-9 2-12z" fill="#ff6a1a"/></svg>';
function startSession(r) { ME = { user: r.user, role: r.role }; CSRF = r.csrf; $('#login').classList.add('hidden'); if (r.totpEnrolRequired) return showEnrol(); boot(); }
async function showLogin() {
  ME = null; CSRF = null; if (ws) { ws.onclose = null; try { ws.close(); } catch {} } $('#app').classList.add('hidden'); const L = $('#login'); L.classList.remove('hidden');
  let st = {}; try { st = await (await fetch('/api/auth/status')).json(); } catch {}
  const prod = st.mode === 'production';
  if (st.setupRequired) {
    L.innerHTML = `<form class="box" id="lf">${LOGO}<h1>PHOENIX X</h1><p class="dim" style="text-align:center;margin:0 0 14px">First-run setup — create the administrator account</p>
    <label class="dim">Administrator username</label><input id="lu" autocomplete="username" placeholder="e.g. soc.admin">
    <label class="dim">Password (min. 12 characters, letters + digits)</label><input id="lp" type="password" autocomplete="new-password">
    ${st.setupTokenRequired ? '<label class="dim">Setup token (PHOENIX_SETUP_TOKEN)</label><input id="lt" type="password">' : ''}
    <button class="btn pri" style="width:100%;padding:10px">Create administrator</button><p id="le" class="st-bad" style="min-height:18px;margin:8px 0 0"></p></form>`;
    $('#lf').onsubmit = async (e) => { e.preventDefault(); try { startSession(await api('/api/auth/setup', 'POST', { username: $('#lu').value, password: $('#lp').value, setupToken: $('#lt')?.value })); } catch (er) { $('#le').textContent = er.message; } };
    return;
  }
  L.innerHTML = `<form class="box" id="lf">${LOGO}<h1>PHOENIX X</h1><p class="dim" style="text-align:center;margin:0 0 18px">Autonomous AI Security Operations ${prod ? '' : '· <b>DEMO</b>'}</p>
  <label class="dim">Username</label><input id="lu" value="${st.demo ? 'admin' : ''}" autocomplete="username"><label class="dim">Password</label><input id="lp" type="password" autocomplete="current-password" ${st.demo ? `value="${esc(st.password)}"` : ''}>
  <div id="totpbox" class="hidden"><label class="dim">Authenticator code</label><input id="lc" inputmode="numeric" maxlength="6" autocomplete="one-time-code"></div>
  <button class="btn pri" style="width:100%;padding:10px">Sign in</button><p id="le" class="st-bad" style="min-height:18px;margin:8px 0 0"></p>
  ${st.demo ? '<p class="note">Demo roles: <b>admin</b> (approve actions), <b>analyst</b> (investigate, launch scenarios), <b>viewer</b> (read-only).</p>' : ''}</form>`;
  $('#lf').onsubmit = async (e) => { e.preventDefault(); try { startSession(await api('/api/auth/login', 'POST', { username: $('#lu').value, password: $('#lp').value, totp: $('#lc').value || undefined })); } catch (er) { $('#le').textContent = er.message; if (/authentication code/i.test(er.message)) { $('#totpbox').classList.remove('hidden'); $('#lc').focus(); } } };
}
async function showEnrol() {
  const L = $('#login'); L.classList.remove('hidden'); $('#app').classList.add('hidden');
  const b = await api('/api/auth/totp/begin', 'POST', {});
  L.innerHTML = `<form class="box" id="lf">${LOGO}<h1>Two-factor required</h1><p class="dim">Administrators must use an authenticator app. Add this key to Google Authenticator / Authy / 1Password (type it in manually):</p><pre class="md" style="user-select:all">${esc(b.secret)}</pre><p class="dim" style="font-size:11px">${esc(b.uri)}</p><label class="dim">6-digit code</label><input id="lc" inputmode="numeric" maxlength="6"><button class="btn pri" style="width:100%;padding:10px">Confirm &amp; continue</button><p id="le" class="st-bad" style="min-height:18px"></p></form>`;
  $('#lf').onsubmit = async (e) => { e.preventDefault(); try { await api('/api/auth/totp/confirm', 'POST', { code: $('#lc').value }); toast('Two-factor enabled. Sign in again with your code.', 'ok'); await api('/api/auth/logout', 'POST', {}).catch(() => {}); showLogin(); } catch (er) { $('#le').textContent = er.message; } };
}

// ---------- websocket ----------
let ws, wsTimer;
function connectWS() {
  clearTimeout(wsTimer); if (!ME) return;
  ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onopen = () => { $('#wsdot').classList.add('ok'); $('#wstxt').textContent = 'live · WebSocket'; };
  ws.onclose = () => { $('#wsdot').classList.remove('ok'); $('#wstxt').textContent = 'reconnecting…'; wsTimer = setTimeout(connectWS, 2000); };
  ws.onmessage = (m) => { try { onMsg(JSON.parse(m.data)); } catch (e) { console.error(e); } };
}
let rt = null; const later = (ms = 250) => { if (!rt) rt = setTimeout(() => { rt = null; render(); }, ms); };
function onMsg({ type, data }) {
  switch (type) {
    case 'event': S.events.push(data); if (S.events.length > 300) S.events.shift(); S.metrics.eventsToday = (S.metrics.eventsToday || 0) + 1; prependEvent(data); updateKpis(); break;
    case 'incident': { const i = S.incidents.findIndex((x) => x.id === data.id); if (i >= 0) S.incidents[i] = data; else { S.incidents.unshift(data); toast(`🚨 New incident <b>${esc(data.id)}</b> — ${esc(data.title)}`); } if (U.detailId === data.id) refreshDetail(); if (U.graphInc === data.id && U.detail?.id !== data.id) refreshDetail(data.id); later(); break; }
    case 'agents': S.agents = data; if (['agents', 'command'].includes(route().page)) later(400); break;
    case 'agent_msg': S.messages.push(data); if (S.messages.length > 100) S.messages.shift(); if (['agents', 'command'].includes(route().page)) later(400); break;
    case 'approval': S.approvals.push(data); toast(`🛡️ <b>Approval requested</b>: ${esc(data.action.description)}`); later(100); break;
    case 'metrics': Object.assign(S.metrics, data); S.assets = data.assets; S.analytics = data.analytics; updateKpis(); if (route().page === 'analytics') later(); break;
    case 'audit': S.audit.push(data); if (S.audit.length > 1500) S.audit.shift(); if (route().page === 'audit') later(800); break;
    case 'scenario': U.narr = data.step === 'DONE' ? { text: 'Scenario events injected. Agents are now working the incident…', done: true, ts: Date.now() } : data.step === 'START' ? { text: 'Simulation started', ts: Date.now() } : { text: data.step, ts: Date.now() }; showNarr(); break;
    case 'notification': S.notifications.push(data); break;
    case 'reset': loadState(); break;
  }
  if (type === 'incident') S.approvals = S.approvals.filter((a) => a.incidentId !== data.id || data.pendingApprovals > 0);
}
function showNarr() { const n = $('#narr'); if (!U.narr) return n.classList.add('hidden'); n.classList.remove('hidden'); n.innerHTML = `<span class="pulse"></span><div><b>LIVE DEMO</b> · ${esc(U.narr.text)}</div>`; clearTimeout(showNarr.t); showNarr.t = setTimeout(() => { if (Date.now() - U.narr.ts > 9000) $('#narr').classList.add('hidden'); }, 10000); }

async function loadState() { const d = await api('/api/state'); Object.assign(S, d); render(); }
async function refreshDetail(id = U.detailId) { if (!id) return; clearTimeout(refreshDetail.t); refreshDetail.t = setTimeout(async () => { try { const d = await api('/api/incidents/' + id); if (U.detailId === id || U.graphInc === id) { U.detail = d; later(50); } } catch {} }, 250); }
const pendingActions = () => S.approvals;
U.cache = {}; U.stamp = {};
function allDetails() { for (const i of S.incidents) { const st = [i.state, i.actions, i.tasks.done, i.tasks.total, i.pendingApprovals, i.alerts, i.status].join('|'); if (U.stamp[i.id] !== st) { U.stamp[i.id] = st; api('/api/incidents/' + i.id).then((d) => { U.cache[i.id] = d; later(300); }).catch(() => {}); } } return S.incidents.map((i) => U.cache[i.id]).filter(Boolean); }

// ---------- routing ----------
function route() { const h = (location.hash || '#/command').slice(2).split('/'); return { page: PAGES.some((p) => p[0] === h[0]) ? h[0] : 'command', arg: h[1] }; }
function render() {
  if (!ME) return;
  const { page, arg } = route(); const el = $('#page');
  if (document.activeElement && ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) && el.contains(document.activeElement)) return;
  $('#nav').innerHTML = PAGES.map(([k, l, ic]) => `<a href="#/${k}" class="${k === page ? 'on' : ''}"><svg viewBox="0 0 24 24"><path d="${ICONS[ic]}"/></svg>${l}${k === 'response' && S.metrics.pendingApprovals ? `<span class="badge">${S.metrics.pendingApprovals}</span>` : ''}${k === 'incidents' && S.metrics.activeIncidents ? `<span class="badge" style="background:#ff6a1a">${S.metrics.activeIncidents}</span>` : ''}</a>`).join('');
  $('#crumb').innerHTML = `Phoenix X / <b>${esc(PAGES.find((p) => p[0] === page)[1])}</b>${arg ? ' / <b>' + esc(arg) + '</b>' : ''}`;
  if (page === 'incidents' && arg && U.detailId !== arg) { U.detailId = arg; U.detail = null; U.tab = 'overview'; refreshDetail(arg); }
  if (page !== 'incidents') U.detailId = null;
  const ab = $('#apbar'); if (ab) { const n = (S.approvals || []).length; ab.innerHTML = n && page !== 'response' ? `<div class="note" style="margin:0 0 12px;border-color:rgba(255,210,74,.6)"><b>⏳ The AI needs your OK for ${n} action${n > 1 ? 's' : ''}.</b> <span class="dim">Press Allow and the AI does it; you can undo it afterwards.</span> <span style="float:right"><a class="btn ghost sm" href="#/response">Review</a> ${isAdmin() ? '<button class="btn ok sm" data-a="allowall">✓ Allow all</button>' : ''}</span></div>` : ''; }
  const st = el.scrollTop; el.innerHTML = (PAGE_FN[page] || (() => ''))(arg); el.scrollTop = st; bind(el);
}
window.addEventListener('hashchange', () => { U.node = null; render(); });
function updateKpis() { for (const el of document.querySelectorAll('[data-kpi]')) { const k = el.dataset.kpi; const v = S.metrics[k]; if (v !== undefined) el.textContent = k === 'avgContainSec' ? (v == null ? '—' : v + 's') : v; } const rg = $('#ringfg'); if (rg) { const r = S.metrics.riskScore || 0; rg.setAttribute('stroke-dasharray', `${(r / 100) * 339} 339`); rg.setAttribute('stroke', r > 70 ? '#ff3b4f' : r > 40 ? '#ff8a2a' : '#3ddc97'); const rv = $('#ringv'); if (rv) rv.textContent = r; } }
function prependEvent(e) {
  const f = $('#feed'); if (!f || U.feedPaused) return; if (U.feedFilter !== 'all' && e.source !== U.feedFilter && e.origin !== U.feedFilter) return;
  f.insertAdjacentHTML('afterbegin', evRow(e, true)); while (f.children.length > 150) f.lastChild.remove();
}
const evDesc = (e) => { const d = [e.user, e.host && e.host !== e.user ? '@' + e.host : '', e.ip ? '← ' + e.ip : '', e.geo ? '(' + e.geo + ')' : '', e.resource || '', e.domain || '', e.count ? '×' + e.count : '', e.bytes ? (e.bytes / 1e6).toFixed(1) + 'MB' : ''].filter(Boolean).join(' '); return `<b>${esc(e.type)}</b> <span class="dim">${esc(d)}</span>`; };
const SUSP = new Set(['login_failed', 'privilege_change', 'file_rename', 'shadow_copy_deleted', 'beacon', 'macro_exec', 'mailbox_rule_created', 'iam_attach_policy', 'create_access_key', 'put_bucket_acl', 'stop_logging', 'lateral_access', 'email_reported', 'email_link_click']);
const evRow = (e, isNew) => `<div class="e ${e.origin === 'scenario' && SUSP.has(e.type) ? 'sus' : ''} ${isNew ? 'new' : ''}"><span class="t">${fmtT(e.ts)}</span><span>${originChip(e.origin)}</span><span><span class="mut">${esc(e.source)}</span> ${evDesc(e)}</span></div>`;

// ---------- charts ----------
function stackedBars(series, keys, colors, w = 560, h = 120) {
  const max = Math.max(1, ...series.map((s) => keys.reduce((a, k) => a + s[k], 0))), bw = w / series.length;
  return `<svg viewBox="0 0 ${w} ${h + 16}" style="width:100%"><g>${series.map((s, i) => { let y = h; return keys.map((k, j) => { const bh = (s[k] / max) * (h - 6); y -= bh; return bh > 0 ? `<rect x="${i * bw + 2}" y="${y}" width="${bw - 4}" height="${bh}" rx="2" fill="${colors[j]}" opacity=".9"/>` : ''; }).join(''); }).join('')}</g><line x1="0" x2="${w}" y1="${h}" y2="${h}" stroke="#223" /><text x="0" y="${h + 12}" fill="#5c6879" font-size="9">-10 min</text><text x="${w}" y="${h + 12}" fill="#5c6879" font-size="9" text-anchor="end">now</text></svg>`;
}
function hbars(obj, color = '#ff6a1a') { const e = Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, 10), m = Math.max(1, ...e.map((x) => x[1])); return e.length ? e.map(([k, v]) => `<div class="between" style="margin:5px 0"><span style="width:38%;font-size:12px" class="dim">${esc(k)}</span><div class="bar sp"><i style="width:${(v / m) * 100}%;background:${color}"></i></div><b class="mono" style="width:44px;text-align:right">${v}</b></div>`).join('') : '<div class="empty">No data yet</div>'; }
function ring() { const r = S.metrics.riskScore || 0; return `<div class="ring"><svg viewBox="0 0 120 120" width="132" height="132"><circle cx="60" cy="60" r="54" fill="none" stroke="#18212e" stroke-width="10"/><circle id="ringfg" cx="60" cy="60" r="54" fill="none" stroke="${r > 70 ? '#ff3b4f' : r > 40 ? '#ff8a2a' : '#3ddc97'}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(r / 100) * 339} 339" style="transition:stroke-dasharray .8s"/></svg><div class="c"><div><b id="ringv">${r}</b><span class="dim" style="font-size:10px;letter-spacing:.1em">RISK</span></div></div></div>`; }

// ---------- attack graph ----------
const KCOL = { user: '#38d6ff', device: '#3ddc97', server: '#34c4a0', ip: '#ff8a2a', domain: '#ff8a2a', file: '#ffd24a', application: '#a78bfa', event: '#ff4d5e' };
const KBAND = { ip: .1, domain: .1, user: .27, event: .5, device: .73, server: .73, file: .9, application: .9 };
const KGLYPH = { user: 'U', device: 'D', server: 'S', ip: 'IP', domain: '@', file: 'F', application: 'A', event: '!' };
function graphSvg(inv, opts = {}) {
  const g = inv?.investigation?.graph || inv?.graph; if (!g || !g.nodes.length) return '<div class="empty">No graph data yet — waiting for investigation.</div>';
  const W = 1000, H = opts.small ? 340 : 560, ev = g.nodes.filter((n) => n.kind === 'event').sort((a, b) => new Date(a.ts) - new Date(b.ts)), step = (W - 140) / Math.max(1, ev.length - 1 || 1);
  const pos = {}; ev.forEach((n, i) => (pos[n.id] = { x: ev.length === 1 ? W / 2 : 70 + i * step, y: H * .5 + (i % 2 ? 22 : -22) }));
  const adj = {}; g.edges.filter((e) => !e.path).forEach((e) => { (adj[e.from] ||= []).push(e.to); });
  const bands = {}; g.nodes.filter((n) => n.kind !== 'event').forEach((n) => { const xs = (adj[n.id] || []).map((t) => pos[t]?.x).filter((x) => x != null); n._x = xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : W / 2; (bands[KBAND[n.kind] ?? .9] ||= []).push(n); });
  for (const [b, arr] of Object.entries(bands)) { arr.sort((a, c) => a._x - c._x); let last = -1e9; const min = opts.small ? 64 : 96; arr.forEach((n, i) => { n._x = Math.max(n._x, last + min); last = n._x; }); const over = last - (W - 40); if (over > 0) arr.forEach((n) => (n._x -= over)); const lo = arr[0]._x - 40; if (lo < 0) arr.forEach((n) => (n._x -= lo)); arr.forEach((n, i) => (pos[n.id] = { x: n._x, y: H * +b + ((i % 2) && (+b === .1 || +b === .9) ? 26 : 0) })); }
  const edges = g.edges.map((e) => { const a = pos[e.from], b = pos[e.to]; if (!a || !b) return ''; if (e.path) { const mx = (a.x + b.x) / 2; return `<path class="ge p" d="M${a.x} ${a.y} Q${mx} ${a.y - 38} ${b.x} ${b.y}" marker-end="url(#ar)"/>`; } return `<line class="ge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`; }).join('');
  const nodes = g.nodes.map((n) => { const p = pos[n.id]; if (!p) return ''; const r = n.kind === 'event' ? 16 : 20, col = KCOL[n.kind] || '#888', mal = n.intel?.verdict === 'malicious', lbl = n.kind === 'event' ? n.label : n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label;
    return `<g class="gn ${U.node === n.id ? 'sel' : ''}" data-node="${esc(n.id)}" transform="translate(${p.x},${p.y})">${n.suspicious ? `<circle r="${r + 7}" fill="${mal ? '#ff3b4f' : col}" opacity=".13"><animate attributeName="r" values="${r + 4};${r + 10};${r + 4}" dur="2.4s" repeatCount="indefinite"/></circle>` : ''}<circle class="b" r="${r}" fill="#0b1119" stroke="${mal ? '#ff3b4f' : col}" stroke-width="${mal ? 3 : 2}"/><text text-anchor="middle" dy="4" style="fill:${col};font-weight:700;font-size:${n.kind === 'ip' ? 9 : 11}px">${KGLYPH[n.kind] || '?'}</text>${opts.small && n.kind !== 'event' ? '' : `<text text-anchor="middle" y="${r + 13}">${esc(lbl)}</text>`}</g>`; }).join('');
  return `<div class="graphbox"><svg viewBox="0 0 ${W} ${H}"><defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#ff6a1a"/></marker></defs>${edges}${nodes}</svg>${opts.small ? '' : `<div class="legend">${Object.entries({ user: 'User', device: 'Device', server: 'Server', ip: 'IP', domain: 'Domain', file: 'File', application: 'App/Service', event: 'Security event' }).map(([k, l]) => `<span><i style="background:${KCOL[k]}"></i>${l}</span>`).join('')}<span><i style="background:none;border:2px solid #ff3b4f"></i>Known-malicious (intel)</span><span style="color:#ff9a5c">┅ attack path</span></div>`}</div>`;
}
function nodePanel(inv) {
  const G = inv.investigation?.graph || inv.graph; const n = G.nodes.find((x) => x.id === U.node); if (!n) return `<div class="card"><h2>Node inspector</h2><div class="empty">Click any node in the graph to inspect its evidence.</div></div>`;
  const items = (inv.evidence?.items || []).filter((e) => n.evidence.includes(e.id)); const E = inv.evidence?.items || [];
  const evs = E.filter((e) => n.evidence.includes(e.id));
  return `<div class="card"><h2>Node inspector</h2><div class="row"><b style="font-size:15px">${esc(n.label)}</b><span class="chip">${esc(n.kind)}</span>${n.suspicious ? '<span class="chip sev-high">suspicious</span>' : ''}</div>
  ${n.summary ? `<p>${esc(n.summary)}</p>` : ''}${n.intel ? `<div class="note">Threat intel (${esc(n.intel.source)}): <b class="${n.intel.verdict === 'malicious' ? 'st-bad' : ''}">${esc(n.intel.verdict)}</b> ${(n.intel.tags || []).map((t) => `<span class="pill">${esc(t)}</span>`).join('')}</div>` : ''}
  <h3>Evidence (${evs.length})</h3>${evs.length ? evs.slice(0, 12).map((e) => `<div class="msg"><div class="h">${fmtT(e.ts)} · ${esc(e.id)} · ${originChip(e.origin)}</div>${evDesc(e)}<pre style="display:block">${esc(JSON.stringify(e.details, null, 1))}</pre></div>`).join('') : '<div class="dim">Entity node — see connected event nodes for evidence.</div>'}</div>`;
}
