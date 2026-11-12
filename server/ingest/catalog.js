'use strict';
// "Connect a platform" catalog: one source of truth for the in-app wizard and the generated docs.
// Placeholders filled by the UI after a key is created: {{HOOK}} = https://phoenix/api/hook/<key>, {{ORIGIN}}, {{HOST}}, {{KEY}}, {{BASIC}} (basic-auth URL).
// Vendor UI labels change over time; steps name the feature, not pixel-exact menus. Plan availability is the vendor's and may change.
const SDK_CODE = `// npm i  (nothing to install: copy phoenix.js from {{ORIGIN}}/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: '{{ORIGIN}}', key: process.env.PHOENIX_KEY });   // key: {{KEY}}

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));`;

const sdk = { id: 'sdk', title: 'Add the PHOENIX SDK to your app code (works on any host)', kind: 'code', format: 'generic', code: SDK_CODE, steps: ['Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host\'s dashboard.', 'Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.', 'On serverless platforms events are sent immediately (no background batching).'], needs: 'Your PHOENIX X server must be reachable over HTTPS from the internet.' };

const PLATFORMS = [
  { id: 'vercel', name: 'Vercel', icon: '▲', blurb: 'Request logs, firewall blocks and deployment/domain/project changes.', methods: [
    { id: 'logs', title: 'Log Drain (requests, WAF, errors)', kind: 'logs', format: 'vercel', signing: 'optional', verify: true,
      steps: ['In Vercel: Team Settings → Drains (log drains), then Add Drain → custom HTTP endpoint.', 'Endpoint URL: {{HOOK}}', 'Delivery format: JSON or NDJSON (both are accepted).', 'If Vercel asks you to verify the endpoint, enter the verification value in "Verify token" below before saving the connection. PHOENIX answers the handshake with the x-vercel-verify header.', '(Optional) set a drain secret in Vercel and paste the same value into "Signing secret" below; PHOENIX then rejects unsigned requests.', 'Vercel plan note: drains/webhooks have historically required a Pro or Enterprise plan; check your plan.'] },
    { id: 'webhook', title: 'Webhook (deployments, domains, project/integration changes)', kind: 'webhook', format: 'vercel-webhook', signing: 'optional',
      steps: ['In Vercel: Team Settings → Webhooks → Create.', 'URL: {{HOOK}}', 'Select events: deployment.*, domain.*, project.removed, integration-configuration.*, and firewall/attack events if offered.', '(Optional) paste the webhook secret into "Signing secret" below to verify signatures (HMAC-SHA1, x-vercel-signature).'] }, sdk] },
  { id: 'render', name: 'Render', icon: '◼', blurb: 'Deploy/service events natively; request logs via the SDK or a log relay.', methods: [
    { id: 'webhook', title: 'Webhook (deploys, service state)', kind: 'webhook', format: 'render-webhook',
      steps: ['In Render: Workspace/Account Settings → Webhooks → Add endpoint.', 'URL: {{HOOK}}', 'Select the deploy and service events you want.'] },
    { id: 'logs', title: 'Log Stream via a relay (advanced)', kind: 'logs', format: 'render',
      steps: ['Render log streams speak syslog (TLS over TCP) to a HOST:PORT you provide; PHOENIX X receives HTTP only, so run a small relay (for example Vector) that converts syslog to HTTP.', 'Relay output: POST JSON {"lines":[...]} to {{HOOK}}. A ready Vector config is in docs/PLATFORMS.md (not tested against Render here).', 'Only structured request lines (JSON/logfmt with ip, path and status) become events; plain app output is ignored.', 'Simpler alternative: use the SDK below, which reports requests and logins directly.'] }, sdk] },
  { id: 'heroku', name: 'Heroku', icon: '♥', blurb: 'Router request logs and API audit lines (config-var changes, deploys).', methods: [
    { id: 'drain', title: 'HTTPS log drain', kind: 'logs', format: 'heroku',
      steps: ['Run this in a terminal with the Heroku CLI (replace APP):', 'heroku drains:add {{BASIC}} -a APP', 'Heroku supports basic-auth credentials inside the drain URL; the password is your ingest key, so keep the URL private.', 'Router lines (IP, path, status) become web events. "Set … config vars by user …" and "Deploy … by user …" lines become change/deploy events.'] }, sdk] },
  { id: 'netlify', name: 'Netlify', icon: '◆', blurb: 'Deploy started/succeeded/failed/locked and rollbacks.', methods: [
    { id: 'webhook', title: 'Deploy notification (outgoing webhook)', kind: 'webhook', format: 'netlify', signing: 'optional',
      steps: ['In Netlify: Project configuration → Notifications → Deploy notifications → Add notification → Outgoing webhook.', 'URL to notify: {{HOOK}}', 'Choose events: Deploy started, succeeded, failed, locked/unlocked, restored.', '(Optional) set a JWS secret in Netlify and paste it into "Signing secret" below; PHOENIX verifies the X-Webhook-Signature (HS256) token.'] }, sdk] },
  { id: 'railway', name: 'Railway', icon: '🚂', blurb: 'Deployment status webhooks.', methods: [
    { id: 'webhook', title: 'Deployment webhook', kind: 'webhook', format: 'railway',
      steps: ['In Railway: Project → Settings → Webhooks → add a webhook.', 'URL: {{HOOK}}', 'The payload mapping is defensive (it accepts the documented deployment-status shape and ignores anything else).'] }, sdk] },
  { id: 'cloudflare', name: 'Cloudflare', icon: '☁', blurb: 'Edge request logs and firewall (WAF) events via Logpush.', methods: [
    { id: 'logpush', title: 'Logpush job (HTTP destination)', kind: 'logs', format: 'cloudflare',
      steps: ['Logpush availability depends on your Cloudflare plan; check your account.', 'Create a Logpush job with an HTTP destination. Destination URL: {{HOOK}}', 'Dataset: http_requests and/or firewall_events. Include at least ClientIP, ClientRequestHost, ClientRequestMethod, ClientRequestURI, EdgeResponseStatus, ClientCountry (and Action, RuleID for firewall_events).', 'PHOENIX accepts gzip and NDJSON and answers Cloudflare\'s destination test.'] }, sdk] },
  { id: 'github', name: 'GitHub', icon: '⌥', blurb: 'Leaked secrets, repo made public, deploy keys, branch-protection removal, force-pushes, new members.', methods: [
    { id: 'webhook', title: 'Repository or organization webhook', kind: 'webhook', format: 'github', signing: 'recommended',
      steps: ['In GitHub: Repository (or Organization) → Settings → Webhooks → Add webhook.', 'Payload URL: {{HOOK}}   ·   Content type: application/json', 'Secret: choose a random string and paste the same value into "Signing secret" below (verifies X-Hub-Signature-256).', 'Select individual events: Secret scanning alerts, Repositories, Deploy keys, Branch protection rules, Members (and Organization for org hooks), Pushes, Dependabot alerts.'] }] },
  { id: 'vps', name: 'VPS / nginx', icon: '▤', blurb: 'DigitalOcean, Hetzner, EC2, Lightsail: tail nginx/Apache and SSH auth logs.', methods: [
    { id: 'ship', title: 'Log shipper script (ships any log file)', kind: 'code', format: 'nginx',
      code: `# nginx / Apache combined access log\nnode scripts/ship-logs.js --url {{ORIGIN}} --key {{KEY}} --format nginx --file /var/log/nginx/access.log\n# SSH logins (use a key created with format "syslog")\nnode scripts/ship-logs.js --url {{ORIGIN}} --key <syslog-key> --format syslog --file /var/log/auth.log`,
      steps: ['Copy scripts/ship-logs.js to the server (Node 18+; no packages needed).', 'Run the commands shown (use systemd or pm2 to keep it running).', 'It remembers its position, batches lines, retries on failure and survives log rotation.'] }, sdk] },
  { id: 'aws', name: 'AWS', icon: '⬢', blurb: 'Amplify, Beanstalk, ECS, Lambda: CloudTrail IAM changes, new keys, public buckets.', methods: [
    { id: 'cloudtrail', title: 'CloudTrail records', kind: 'logs', format: 'cloudtrail',
      steps: ['Have a small Lambda/cron job read new CloudTrail log files from S3 and POST {"Records":[…]} to {{HOOK}}.', 'Or test manually: aws cloudtrail lookup-events … | curl -X POST {{HOOK}} --data-binary @-'] }, sdk] },
  { id: 'other', name: 'Any other host', icon: '✚', blurb: 'Fly.io, Azure, GCP, DO App Platform, Koyeb: the SDK works anywhere Node runs; JSON from anything else.', methods: [sdk,
    { id: 'generic', title: 'Plain HTTP / curl (any language)', kind: 'code', format: 'generic',
      code: `curl -X POST {{HOOK}} -H "content-type: application/json" \\\n  -d '{"events":[{"source":"authentication","type":"login_failed","user":"alice","ip":"203.0.113.9"}]}'`,
      steps: ['Send events in PHOENIX\'s JSON schema from any language. See docs/INTEGRATIONS.md for fields.'] }] },
];
module.exports = { PLATFORMS };
