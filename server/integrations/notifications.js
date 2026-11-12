'use strict';
// Notifications. A message is only marked "delivered" when the PROVIDER returned a success response.
// Without credentials it is recorded in a local outbox as "simulated" (clearly labelled NOT SENT).
const { uid } = require('../core/util');
const sim = require('../sim/enterprise');
const audit = require('../core/audit');
const bus = require('../core/bus');

const E = process.env;
const providers = {
  slack: { on: () => !!E.SLACK_WEBHOOK_URL, send: async (m) => { const r = await post(E.SLACK_WEBHOOK_URL, { text: `*${m.subject}*\n${m.body}` }); const t = await r.text(); if (!r.ok || t !== 'ok') throw new Error(`Slack HTTP ${r.status} ${t.slice(0, 80)}`); return { confirmation: 'slack webhook returned ok' }; } },
  teams: { on: () => !!E.TEAMS_WEBHOOK_URL, send: async (m) => { const r = await post(E.TEAMS_WEBHOOK_URL, { text: `**${m.subject}**\n\n${m.body}` }); if (!r.ok) throw new Error('Teams HTTP ' + r.status); return { confirmation: 'teams webhook HTTP ' + r.status }; } },
  email: { on: () => !!(E.RESEND_API_KEY && E.NOTIFY_EMAIL_TO && E.NOTIFY_EMAIL_FROM), send: async (m) => { const r = await post('https://api.resend.com/emails', { from: E.NOTIFY_EMAIL_FROM, to: E.NOTIFY_EMAIL_TO.split(','), subject: m.subject, text: m.body }, { Authorization: 'Bearer ' + E.RESEND_API_KEY }); const j = await r.json().catch(() => ({})); if (!r.ok || !j.id) throw new Error('Resend HTTP ' + r.status); return { confirmation: 'resend id ' + j.id }; } },
  sms: { on: () => !!(E.TWILIO_ACCOUNT_SID && E.TWILIO_AUTH_TOKEN && E.TWILIO_FROM && E.NOTIFY_SMS_TO), send: async (m) => { const body = new URLSearchParams({ From: E.TWILIO_FROM, To: E.NOTIFY_SMS_TO, Body: (m.subject + ' ' + m.body).slice(0, 300) }); const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${E.TWILIO_ACCOUNT_SID}/Messages.json`, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(E.TWILIO_ACCOUNT_SID + ':' + E.TWILIO_AUTH_TOKEN).toString('base64') }, body, signal: AbortSignal.timeout(8000) }); const j = await r.json().catch(() => ({})); if (!r.ok || !j.sid) throw new Error('Twilio HTTP ' + r.status); return { confirmation: 'twilio sid ' + j.sid }; } },
};
function post(url, json, headers = {}) { return fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(json), signal: AbortSignal.timeout(8000) }); }

async function notify(incident, subject, body, channels = ['slack', 'email', 'sms']) {
  const out = [];
  for (const ch of channels) {
    const rec = { id: uid('ntf'), channel: ch, subject, ts: new Date().toISOString(), incidentId: incident.id };
    if (providers[ch].on()) {
      try { const r = await providers[ch].send({ subject, body }); Object.assign(rec, { status: 'delivered', provider: ch, ...r }); }
      catch (e) { Object.assign(rec, { status: 'failed', error: e.message }); }
    } else Object.assign(rec, { status: 'simulated', provider: 'local-outbox', confirmation: null, note: 'NOT SENT — no credentials configured for ' + ch });
    sim.env.outbox.push({ ...rec, body });
    audit.log('NOTIFIER', 'NOTIFICATION_' + rec.status.toUpperCase(), { channel: ch, subject, confirmation: rec.confirmation || null, error: rec.error }, incident.id);
    bus.emit('notification', rec); out.push(rec);
  }
  return out;
}
const status = () => Object.fromEntries(Object.entries(providers).map(([k, p]) => [k, p.on() ? 'configured' : 'simulator']));
module.exports = { notify, status };
