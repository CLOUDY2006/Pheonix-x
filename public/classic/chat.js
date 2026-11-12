'use strict';
// Compact assistant dock (bottom-right). Collapsed it is one small bar; open it and just tell the AI what to do.
(() => {
  const css = `#chat{position:fixed;right:18px;bottom:0;z-index:900;width:min(380px,calc(100vw - 24px));font-size:13px}
#chat .bar{display:flex;align-items:center;gap:8px;padding:9px 14px;background:var(--panel2);border:1px solid var(--line2);border-bottom:0;border-radius:10px 10px 0 0;cursor:pointer;box-shadow:0 -4px 20px rgba(0,0,0,.35)}
#chat .bar b{flex:1;font-weight:600}#chat .bar .dot{width:8px;height:8px;border-radius:50%;background:var(--gr)}
#chat .badge2{background:var(--ph);color:#000;border-radius:9px;padding:0 7px;font-size:11px;font-weight:700}
#chat .pane{display:none;flex-direction:column;height:min(460px,calc(100vh - 120px));background:var(--panel);border:1px solid var(--line2);border-top:0}
#chat.open .pane{display:flex}#chat.open .bar{border-radius:10px 10px 0 0}
#chat .msgs{flex:1;overflow:auto;padding:10px;display:flex;flex-direction:column;gap:8px}
#chat .m{max-width:88%;padding:8px 10px;border-radius:10px;line-height:1.45;white-space:pre-wrap;word-break:break-word}
#chat .m.me{align-self:flex-end;background:rgba(255,106,26,.18);border:1px solid rgba(255,106,26,.4)}
#chat .m.ai{align-self:flex-start;background:var(--panel2);border:1px solid var(--line)}
#chat .m code{background:#0006;padding:1px 4px;border-radius:4px;font-family:var(--mono,monospace);user-select:all}
#chat .chips{display:flex;flex-wrap:wrap;gap:6px;padding:0 10px 8px}
#chat .chips button{background:transparent;color:var(--tx);border:1px solid var(--line2);border-radius:14px;padding:4px 10px;cursor:pointer;font-size:12px}
#chat .chips button:hover{border-color:var(--ph);color:var(--ph2)}
#chat form{display:flex;gap:6px;padding:8px;border-top:1px solid var(--line)}
#chat input{flex:1;background:var(--bg2);color:var(--tx);border:1px solid var(--line2);border-radius:8px;padding:8px 10px}
#chat form .ic{background:var(--panel2);color:var(--tx);border:1px solid var(--line2);width:38px;padding:0;font-size:16px}
#chat form .ic.on{background:var(--rd);color:#fff;border-color:var(--rd);animation:phxp 1s infinite}
@keyframes phxp{50%{opacity:.6}}
#chat form button{background:var(--ph);color:#000;border:0;border-radius:8px;padding:0 14px;font-weight:700;cursor:pointer}
@media(max-width:600px){#chat{right:8px}}`;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
  const el = document.createElement('div'); el.id = 'chat'; el.className = 'hidden';
  el.innerHTML = `<div class="bar" id="chat-bar" role="button" tabindex="0" aria-label="Open the AI assistant"><i class="dot"></i><b>Ask PHOENIX AI</b><span id="chat-badge" class="badge2" style="display:none"></span><span id="chat-tog" aria-hidden="true">▲</span></div>
  <div class="pane"><div class="msgs" id="chat-msgs" aria-live="polite"></div><div class="chips" id="chat-chips"></div><form id="chat-form" autocomplete="off"><input id="chat-in" maxlength="300" placeholder="Type or press 🎤 and speak" aria-label="Message"><button type="button" class="ic" id="chat-mic" title="Speak a command" aria-label="Speak a command">🎤</button><button type="button" class="ic" id="chat-spk" title="Read answers aloud" aria-label="Read answers aloud">🔇</button><button>Send</button></form></div>`;
  document.body.appendChild(el);
  const $c = (id) => document.getElementById(id), msgs = $c('chat-msgs');
  const esc2 = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const md = (t) => esc2(t).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>');
  let hist = []; try { hist = JSON.parse(sessionStorage.getItem('phx-chat') || '[]'); } catch { /* storage may be unavailable */ }
  const save = () => { try { sessionStorage.setItem('phx-chat', JSON.stringify(hist.slice(-40))); } catch { /* ignore */ } };
  const add = (who, text, store = true) => { const d = document.createElement('div'); d.className = 'm ' + who; d.innerHTML = who === 'ai' ? md(text) : esc2(text); msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight; if (store) { hist.push({ who, text }); save(); } };
  const chips = (list) => { const c = $c('chat-chips'); c.innerHTML = ''; for (const x of list || []) { const b = document.createElement('button'); b.type = 'button'; b.textContent = x.label; b.onclick = () => send(x.send, x.label); c.appendChild(b); } };
  const QUICK = [{ label: 'Status', send: 'status' }, { label: "What's blocked?", send: "what's blocked" }, { label: 'What needs me?', send: 'what needs me' }, { label: 'Help', send: 'help' }];
  async function send(text, shown) {
    text = (text || '').trim(); if (!text) return; add('me', shown || text); chips([]);
    const w = document.createElement('div'); w.className = 'm ai'; w.textContent = '…'; msgs.appendChild(w); msgs.scrollTop = msgs.scrollHeight;
    try {
      const r = await api('/api/chat', 'POST', { message: text }); w.remove(); add('ai', r.reply); say(r.reply); chips(r.choices && r.choices.length ? r.choices : QUICK);
      if (typeof loadState === 'function') { U.stamp = {}; loadState().then(() => setTimeout(() => render(), 300)).catch(() => {}); }
    } catch (e) { w.remove(); add('ai', '⚠️ ' + e.message); chips(QUICK); }
  }
  // ---- voice: speech-to-text for commands, optional text-to-speech for answers (browser built-ins) ----
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition; let rec = null, listening = false, speak = false;
  try { speak = sessionStorage.getItem('phx-chat-speak') === '1'; } catch { /* ignore */ }
  const spk = $c('chat-spk'), mic = $c('chat-mic'); const paintSpk = () => { spk.textContent = speak ? '🔊' : '🔇'; spk.title = speak ? 'Answers are read aloud (click to mute)' : 'Read answers aloud'; }; paintSpk();
  spk.onclick = () => { speak = !speak; paintSpk(); try { sessionStorage.setItem('phx-chat-speak', speak ? '1' : ''); } catch { /* ignore */ } if (!speak) window.speechSynthesis?.cancel(); };
  const say = (t) => { if (!speak || !window.speechSynthesis) return; const s = new SpeechSynthesisUtterance(String(t).replace(/[*`_]/g, '').replace(/[✅⚠️🚫🔑🛡️🧪❌⏳⏭️•]/g, '').slice(0, 400)); s.lang = navigator.language || 'en-US'; window.speechSynthesis.cancel(); window.speechSynthesis.speak(s); };
  window.__phxSay = say;
  if (!SR) { mic.disabled = true; mic.title = 'Voice input is not supported in this browser (try Chrome, Edge or Safari)'; mic.style.opacity = .4; }
  else mic.onclick = () => {
    if (listening) { try { rec.stop(); } catch { /* ignore */ } return; }
    rec = new SR(); rec.lang = navigator.language || 'en-US'; rec.interimResults = true; rec.maxAlternatives = 1; rec.continuous = false; const inp = $c('chat-in'); let finalText = '';
    rec.onstart = () => { listening = true; mic.classList.add('on'); inp.placeholder = 'Listening… say e.g. "block this IP"'; };
    rec.onresult = (e) => { let t = ''; for (const r of e.results) { t += r[0].transcript; if (r.isFinal) finalText = t; } inp.value = t; };
    rec.onerror = (e) => { add('ai', e.error === 'not-allowed' ? '🎤 Microphone permission was denied. Allow it in the browser address bar and try again.' : e.error === 'no-speech' ? '🎤 I did not hear anything.' : '🎤 Voice input problem: ' + e.error); };
    rec.onend = () => { listening = false; mic.classList.remove('on'); inp.placeholder = 'Type or press 🎤 and speak'; const t = (finalText || inp.value).trim(); inp.value = ''; if (t) send(t); };
    try { rec.start(); } catch { /* already started */ }
  };
  function open(v) { el.classList.toggle('open', v); $c('chat-tog').textContent = v ? '▼' : '▲'; try { sessionStorage.setItem('phx-chat-open', v ? '1' : ''); } catch { /* ignore */ } if (v) setTimeout(() => $c('chat-in').focus(), 50); }
  $c('chat-bar').onclick = () => open(!el.classList.contains('open')); $c('chat-bar').onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(!el.classList.contains('open')); } };
  $c('chat-form').onsubmit = (e) => { e.preventDefault(); const i = $c('chat-in'); const v = i.value; i.value = ''; send(v); };
  for (const h of hist) add(h.who, h.text, false); if (!hist.length) add('ai', "Hi, I'm PHOENIX AI. I detect, investigate, contain and recover on my own, and you can tell me what to do here. Try **unblock sam**, **what needs me?** or **help**.", true);
  chips(QUICK);
  // show only once signed in; badge = actions waiting for you
  setInterval(() => { const on = typeof ME !== 'undefined' && !!ME && !document.querySelector('#app.hidden'); el.classList.toggle('hidden', !on); const n = (typeof S !== 'undefined' && S.approvals ? S.approvals.length : 0); const b = $c('chat-badge'); b.style.display = n ? '' : 'none'; b.textContent = n; }, 700);
  try { if (sessionStorage.getItem('phx-chat-open')) open(true); } catch { /* ignore */ }
})();
