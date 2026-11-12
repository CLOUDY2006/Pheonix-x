# Connecting deployment platforms

> Generated from the in-app wizard (**Connect a Platform** page). The wizard is easier: it creates the key for you and fills in your real URLs.
> Vendor dashboards change; the steps name the feature rather than exact menu paths. Plan availability (for example Vercel Drains or Cloudflare Logpush) is decided by the vendor.

**How it works.** Every connection is a *key*. Create one per platform/source in **Connect a Platform** (or Settings → Ingest keys). The key authenticates in any of three ways, whichever the platform supports:
1. URL: `https://YOUR-PHOENIX/api/hook/<KEY>` (works everywhere, even when a platform cannot set headers)
2. Header: `x-api-key: <KEY>`
3. HTTP Basic password (used by Heroku drains)

A key is bound to one format, can be revoked any time, and is stored only as a SHA-256 hash. Treat a hook URL like a password. For platforms that sign webhooks (Vercel, GitHub, Netlify) also set a **signing secret** on the connection and PHOENIX rejects anything not signed.

**What PHOENIX detects from these sources**
| Signal | Detection |
|---|---|
| Scanner paths (`/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`…) from one IP | **R-WEB-PROBE** Web Reconnaissance |
| SQLi / XSS / traversal / log4shell fragments in request paths | **R-WEB-INJECT** Web Application Attack |
| Floods of 4xx from one IP | **R-WEB-FLOOD** |
| Repeated WAF blocks (Vercel Firewall, Cloudflare) | **R-WEB-WAF** |
| 401/403 on POST `/login`-style paths, repeated | **R-BRUTE / R-SPRAY** (credential stuffing) |
| Leaked secret, repo made public, deploy key added, branch protection removed, force-push, new member | **R-PLATFORM-*** |
| Env-var / domain / project / integration changes on the platform | **R-PLATFORM-*** |

Thresholds are tunable: `PHOENIX_TH_WEB_PROBE` (5 distinct paths/5 min), `PHOENIX_TH_WEB_INJECT` (3), `PHOENIX_TH_WEB_4XX` (60/min), `PHOENIX_TH_WEB_WAF` (10/5 min).

**Honest scope.** PHOENIX X sees what the platform sends it. Vercel/Netlify/Render/Railway do not expose your *host* logs the way a VPS does, so detection there is about HTTP traffic, deploys and account/config changes. Request-level detection is only as good as the log fields the platform provides (IP, path, status). Containment (blocking an IP, suspending a user) always goes through your connectors or a human task; PHOENIX does not change your Vercel/Render/Heroku settings itself.


## ▲ Vercel
Request logs, firewall blocks and deployment/domain/project changes.

### Log Drain (requests, WAF, errors)
Key format: `vercel` · signing secret: optional

1. In Vercel: Team Settings → Drains (log drains), then Add Drain → custom HTTP endpoint.
2. Endpoint URL: https://YOUR-PHOENIX/api/hook/<KEY>
3. Delivery format: JSON or NDJSON (both are accepted).
4. If Vercel asks you to verify the endpoint, enter the verification value in "Verify token" below before saving the connection. PHOENIX answers the handshake with the x-vercel-verify header.
5. (Optional) set a drain secret in Vercel and paste the same value into "Signing secret" below; PHOENIX then rejects unsigned requests.
6. Vercel plan note: drains/webhooks have historically required a Pro or Enterprise plan; check your plan.

### Webhook (deployments, domains, project/integration changes)
Key format: `vercel-webhook` · signing secret: optional

1. In Vercel: Team Settings → Webhooks → Create.
2. URL: https://YOUR-PHOENIX/api/hook/<KEY>
3. Select events: deployment.*, domain.*, project.removed, integration-configuration.*, and firewall/attack events if offered.
4. (Optional) paste the webhook secret into "Signing secret" below to verify signatures (HMAC-SHA1, x-vercel-signature).

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## ◼ Render
Deploy/service events natively; request logs via the SDK or a log relay.

### Webhook (deploys, service state)
Key format: `render-webhook`

1. In Render: Workspace/Account Settings → Webhooks → Add endpoint.
2. URL: https://YOUR-PHOENIX/api/hook/<KEY>
3. Select the deploy and service events you want.

### Log Stream via a relay (advanced)
Key format: `render`

1. Render log streams speak syslog (TLS over TCP) to a HOST:PORT you provide; PHOENIX X receives HTTP only, so run a small relay (for example Vector) that converts syslog to HTTP.
2. Relay output: POST JSON {"lines":[...]} to https://YOUR-PHOENIX/api/hook/<KEY>. A ready Vector config is in docs/PLATFORMS.md (not tested against Render here).
3. Only structured request lines (JSON/logfmt with ip, path and status) become events; plain app output is ignored.
4. Simpler alternative: use the SDK below, which reports requests and logins directly.

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## ♥ Heroku
Router request logs and API audit lines (config-var changes, deploys).

### HTTPS log drain
Key format: `heroku`

1. Run this in a terminal with the Heroku CLI (replace APP):
2. heroku drains:add https://phoenix:<KEY>@YOUR-PHOENIX/api/ingest/heroku -a APP
3. Heroku supports basic-auth credentials inside the drain URL; the password is your ingest key, so keep the URL private.
4. Router lines (IP, path, status) become web events. "Set … config vars by user …" and "Deploy … by user …" lines become change/deploy events.

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## ◆ Netlify
Deploy started/succeeded/failed/locked and rollbacks.

### Deploy notification (outgoing webhook)
Key format: `netlify` · signing secret: optional

1. In Netlify: Project configuration → Notifications → Deploy notifications → Add notification → Outgoing webhook.
2. URL to notify: https://YOUR-PHOENIX/api/hook/<KEY>
3. Choose events: Deploy started, succeeded, failed, locked/unlocked, restored.
4. (Optional) set a JWS secret in Netlify and paste it into "Signing secret" below; PHOENIX verifies the X-Webhook-Signature (HS256) token.

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## 🚂 Railway
Deployment status webhooks.

### Deployment webhook
Key format: `railway`

1. In Railway: Project → Settings → Webhooks → add a webhook.
2. URL: https://YOUR-PHOENIX/api/hook/<KEY>
3. The payload mapping is defensive (it accepts the documented deployment-status shape and ignores anything else).

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## ☁ Cloudflare
Edge request logs and firewall (WAF) events via Logpush.

### Logpush job (HTTP destination)
Key format: `cloudflare`

1. Logpush availability depends on your Cloudflare plan; check your account.
2. Create a Logpush job with an HTTP destination. Destination URL: https://YOUR-PHOENIX/api/hook/<KEY>
3. Dataset: http_requests and/or firewall_events. Include at least ClientIP, ClientRequestHost, ClientRequestMethod, ClientRequestURI, EdgeResponseStatus, ClientCountry (and Action, RuleID for firewall_events).
4. PHOENIX accepts gzip and NDJSON and answers Cloudflare's destination test.

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## ⌥ GitHub
Leaked secrets, repo made public, deploy keys, branch-protection removal, force-pushes, new members.

### Repository or organization webhook
Key format: `github` · signing secret: recommended

1. In GitHub: Repository (or Organization) → Settings → Webhooks → Add webhook.
2. Payload URL: https://YOUR-PHOENIX/api/hook/<KEY>   ·   Content type: application/json
3. Secret: choose a random string and paste the same value into "Signing secret" below (verifies X-Hub-Signature-256).
4. Select individual events: Secret scanning alerts, Repositories, Deploy keys, Branch protection rules, Members (and Organization for org hooks), Pushes, Dependabot alerts.

## ▤ VPS / nginx
DigitalOcean, Hetzner, EC2, Lightsail: tail nginx/Apache and SSH auth logs.

### Log shipper script (ships any log file)
Key format: `nginx`

1. Copy scripts/ship-logs.js to the server (Node 18+; no packages needed).
2. Run the commands shown (use systemd or pm2 to keep it running).
3. It remembers its position, batches lines, retries on failure and survives log rotation.

```
# nginx / Apache combined access log
node scripts/ship-logs.js --url https://YOUR-PHOENIX --key <KEY> --format nginx --file /var/log/nginx/access.log
# SSH logins (use a key created with format "syslog")
node scripts/ship-logs.js --url https://YOUR-PHOENIX --key <syslog-key> --format syslog --file /var/log/auth.log
```

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## ⬢ AWS
Amplify, Beanstalk, ECS, Lambda: CloudTrail IAM changes, new keys, public buckets.

### CloudTrail records
Key format: `cloudtrail`

1. Have a small Lambda/cron job read new CloudTrail log files from S3 and POST {"Records":[…]} to https://YOUR-PHOENIX/api/hook/<KEY>.
2. Or test manually: aws cloudtrail lookup-events … | curl -X POST https://YOUR-PHOENIX/api/hook/<KEY> --data-binary @-

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

## ✚ Any other host
Fly.io, Azure, GCP, DO App Platform, Koyeb: the SDK works anywhere Node runs; JSON from anything else.

### Add the PHOENIX SDK to your app code (works on any host)
Key format: `generic`

*Your PHOENIX X server must be reachable over HTTPS from the internet.*

1. Create the connection below, then store the key as the environment variable PHOENIX_KEY in your host's dashboard.
2. Copy the one-file SDK into your project and add the lines shown. It never throws and never blocks your responses.
3. On serverless platforms events are sent immediately (no background batching).

```
// npm i  (nothing to install: copy phoenix.js from https://YOUR-PHOENIX/sdk/phoenix.js into your project)
const { createPhoenix } = require('./phoenix');           // ESM: import { createPhoenix } from './phoenix.js'
const phx = createPhoenix({ url: 'https://YOUR-PHOENIX', key: process.env.PHOENIX_KEY });   // key: <KEY>

app.use(phx.middleware());                                  // Express/Connect: records every request (status, path, IP)
// in your login handler:
if (!ok) phx.loginFailed({ user: email, ip: req.ip });
else     phx.loginSucceeded({ user: email, ip: req.ip, country: req.headers['x-vercel-ip-country'] });
// Next.js App Router route handler:   export const POST = phx.withPhoenix(async (req) => Response.json({ ok: true }));
```

### Plain HTTP / curl (any language)
Key format: `generic`

1. Send events in PHOENIX's JSON schema from any language. See docs/INTEGRATIONS.md for fields.

```
curl -X POST https://YOUR-PHOENIX/api/hook/<KEY> -H "content-type: application/json" \
  -d '{"events":[{"source":"authentication","type":"login_failed","user":"alice","ip":"203.0.113.9"}]}'
```

## Appendix: Render log stream via a Vector relay (untested against Render)
Render sends syslog (TLS/TCP) to a `HOST:PORT`. Run Vector next to PHOENIX (or anywhere with a public TLS TCP port), then point the Render Log Stream at it:
```toml
# vector.toml
[sources.render]
type = "syslog"
address = "0.0.0.0:6514"
mode = "tcp"
# add a [sources.render.tls] section with your certificate, as Render requires TLS

[transforms.lines]
type = "remap"
inputs = ["render"]
source = '''
. = { "lines": [ string!(.message) ] }
'''

[sinks.phoenix]
type = "http"
inputs = ["lines"]
uri = "https://YOUR-PHOENIX/api/hook/<RENDER-LOG-KEY>"
method = "post"
encoding.codec = "json"
```
Because Vector passes the syslog *message* only, put a structured line in your app logs (JSON or logfmt with `ip`, `path`, `status`). The SDK is simpler and works without the relay.
