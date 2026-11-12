'use strict';
// LEAKED-SECRET AUTO-RESPONSE. When GitHub secret scanning reports an exposed key, find which of your services hold a matching
// variable (names only), compute the blast radius, and prepare a recovery plan PREVIEW (an admin still approves).
const graph = require('./graph'); const blast = require('./blast'); const recover = require('./recover');
const MAP = [[/stripe/i, /^STRIPE_/i, 'Stripe'], [/supabase/i, /SUPABASE/i, 'Supabase'], [/openai/i, /^OPENAI_/i, 'OpenAI'], [/anthropic/i, /^ANTHROPIC_/i, 'Anthropic'], [/aws|amazon/i, /^(AWS_|S3_)/i, 'AWS'], [/github/i, /^(GITHUB|GH_)/i, 'GitHub'], [/slack/i, /^SLACK_/i, 'Slack'], [/twilio/i, /^TWILIO_/i, 'Twilio'], [/sendgrid/i, /^SENDGRID_/i, 'SendGrid'], [/resend/i, /^RESEND_/i, 'Resend'], [/google|gcp|firebase/i, /^(GOOGLE|GCP|FIREBASE)/i, 'Google'], [/mongo|postgres|database|mysql|redis/i, /(DATABASE_URL|POSTGRES|MONGO|MYSQL|REDIS)/i, 'database'], [/vercel/i, /^VERCEL_/i, 'Vercel'], [/netlify/i, /^NETLIFY_/i, 'Netlify'], [/heroku/i, /^HEROKU_/i, 'Heroku'], [/render/i, /^RENDER_/i, 'Render']];
const isLeak = (a) => a.rule === 'R-PLATFORM-SECRET-EXPOSED';
function secretTypeOf(text) { const m = /secret scanning:\s*([^]+?)(?: by | on |$)/i.exec(text || ''); return (m ? m[1] : text || '').trim().slice(0, 80); }
async function forIncident(inc, by = 'system') {
  const a = (inc.alerts || []).find(isLeak); if (!a) return null;
  const type = secretTypeOf(a.evidenceSummary), repo = (a.affected?.resources || [])[0] || null;
  const hit = MAP.find(([t]) => t.test(type)), vars = graph.nodes().filter((n) => n.type === 'secret' && hit && hit[1].test(n.meta?.variable || ''));
  const out = { at: new Date().toISOString(), secretType: type, repo, provider: hit?.[2] || null, matched: vars.map((n) => ({ id: n.id, name: n.name })), summary: '' };
  const origins = vars.length ? vars.map((n) => n.id) : (repo && graph.find(repo)[0] ? [graph.find(repo)[0].id] : []);
  if (origins.length) { const b = blast.compute(origins); out.blast = { affected: b.counts.total, deployments: b.connectedDeployments, secrets: b.exposedSecrets, caveat: b.caveat }; }
  if (vars.length) { try { const plan = await recover.create({ scenario: 'credential', target: vars[0].id }, by); out.planId = plan.id; out.readiness = plan.readiness; } catch (e) { out.planError = String(e.message).slice(0, 120); } }
  out.summary = vars.length ? `Exposed ${type}${repo ? ' in ' + repo : ''}. ${vars.length} matching variable(s) found on ${out.blast?.deployments?.join(', ') || 'your services'}. A recovery plan is ready for your approval.` : `Exposed ${type}${repo ? ' in ' + repo : ''}. No matching variable was found in the dependency map: rotate the key at its provider and check the repo history.`;
  return out;
}
module.exports = { forIncident, isLeak, secretTypeOf, MAP };
