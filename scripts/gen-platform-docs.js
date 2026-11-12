'use strict';
// Generates docs/PLATFORMS.md from the same catalog the in-app wizard uses, so docs and UI never drift:  node scripts/gen-platform-docs.js
const fs = require('fs'); const path = require('path'); const { PLATFORMS } = require('../server/ingest/catalog');
const fill = (t) => t.replaceAll('{{HOOK}}', 'https://YOUR-PHOENIX/api/hook/<KEY>').replaceAll('{{BASIC}}', 'https://phoenix:<KEY>@YOUR-PHOENIX/api/ingest/heroku').replaceAll('{{ORIGIN}}', 'https://YOUR-PHOENIX').replaceAll('{{HOST}}', 'YOUR-PHOENIX').replaceAll('{{KEY}}', '<KEY>');
let md = `# Connecting deployment platforms

> Generated from the in-app wizard (**Connect a Platform** page). The wizard is easier: it creates the key for you and fills in your real URLs.
> Vendor dashboards change; the steps name the feature rather than exact menu paths. Plan availability (for example Vercel Drains or Cloudflare Logpush) is decided by the vendor.

**How it works.** Every connection is a *key*. Create one per platform/source in **Connect a Platform** (or Settings → Ingest keys). The key authenticates in any of three ways, whichever the platform supports:
1. URL: \`https://YOUR-PHOENIX/api/hook/<KEY>\` (works everywhere, even when a platform cannot set headers)
2. Header: \`x-api-key: <KEY>\`
3. HTTP Basic password (used by Heroku drains)

A key is bound to one format, can be revoked any time, and is stored only as a SHA-256 hash. Treat a hook URL like a password. For platforms that sign webhooks (Vercel, GitHub, Netlify) also set a **signing secret** on the connection and PHOENIX rejects anything not signed.

**What PHOENIX detects from these sources**
| Signal | Detection |
|---|---|
| Scanner paths (\`/.env\`, \`/.git\`, \`/wp-admin\`, \`/phpmyadmin\`…) from one IP | **R-WEB-PROBE** Web Reconnaissance |
| SQLi / XSS / traversal / log4shell fragments in request paths | **R-WEB-INJECT** Web Application Attack |
| Floods of 4xx from one IP | **R-WEB-FLOOD** |
| Repeated WAF blocks (Vercel Firewall, Cloudflare) | **R-WEB-WAF** |
| 401/403 on POST \`/login\`-style paths, repeated | **R-BRUTE / R-SPRAY** (credential stuffing) |
| Leaked secret, repo made public, deploy key added, branch protection removed, force-push, new member | **R-PLATFORM-*** |
| Env-var / domain / project / integration changes on the platform | **R-PLATFORM-*** |

Thresholds are tunable: \`PHOENIX_TH_WEB_PROBE\` (5 distinct paths/5 min), \`PHOENIX_TH_WEB_INJECT\` (3), \`PHOENIX_TH_WEB_4XX\` (60/min), \`PHOENIX_TH_WEB_WAF\` (10/5 min).

**Honest scope.** PHOENIX X sees what the platform sends it. Vercel/Netlify/Render/Railway do not expose your *host* logs the way a VPS does, so detection there is about HTTP traffic, deploys and account/config changes. Request-level detection is only as good as the log fields the platform provides (IP, path, status). Containment (blocking an IP, suspending a user) always goes through your connectors or a human task; PHOENIX does not change your Vercel/Render/Heroku settings itself.

`;
for (const p of PLATFORMS) {
  md += `\n## ${p.icon} ${p.name}\n${p.blurb}\n`;
  for (const m of p.methods) {
    md += `\n### ${m.title}\nKey format: \`${m.format}\`${m.signing ? ` · signing secret: ${m.signing}` : ''}\n\n`;
    if (m.needs) md += `*${m.needs}*\n\n`;
    m.steps.forEach((s, i) => (md += `${i + 1}. ${fill(s)}\n`));
    if (m.code) md += `\n\`\`\`\n${fill(m.code)}\n\`\`\`\n`;
  }
}
md += `
## Appendix: Render log stream via a Vector relay (untested against Render)
Render sends syslog (TLS/TCP) to a \`HOST:PORT\`. Run Vector next to PHOENIX (or anywhere with a public TLS TCP port), then point the Render Log Stream at it:
\`\`\`toml
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
\`\`\`
Because Vector passes the syslog *message* only, put a structured line in your app logs (JSON or logfmt with \`ip\`, \`path\`, \`status\`). The SDK is simpler and works without the relay.
`;
fs.writeFileSync(path.join(__dirname, '..', 'docs', 'PLATFORMS.md'), md); console.log('wrote docs/PLATFORMS.md (' + md.length + ' bytes)');
