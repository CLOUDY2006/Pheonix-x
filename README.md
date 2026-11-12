# 🔥 PROJECT PHOENIX X
### Detect. Investigate. Contain. Recover.
#### Autonomous Application Security & Recovery: know what is affected, know how to recover, prove that recovery worked.

An autonomous, multi-agent Security Operations Center. Six specialised agents detect threats, investigate and correlate evidence, enrich indicators, plan containment under a permission policy, obtain human approval, execute only whitelisted actions, drive recovery, and verify the result, with a tamper-evident audit trail.

**New: Application Resilience** (see [docs/RESILIENCE.md](docs/RESILIENCE.md)): a dependency map across Vercel / Render / Netlify / Heroku / Supabase / GitHub, blast-radius analysis, a recovery **rehearsal** that scores readiness without changing anything, approval-gated **safe recovery** (real redeploy/restart with a recorded rollback), a **verification** engine that proves recovery with real probes, and **incident memory** that suggests the fix that worked last time.

**Also new:** leaked-secret auto-response, posture scan, scheduled game-day drills, plain-language incident briefings, and chat channels (Telegram / Slack / Discord / email) for alerts and commands. Approvals stay in the app: see [docs/CHANNELS.md](docs/CHANNELS.md).

**Two modes, one codebase**

| | **Demo mode** (default) | **Production mode** |
|---|---|---|
| Data | simulated enterprise + synthetic attacks | **your real logs** via `/api/ingest`; starts empty |
| Containment | simulator | **connectors** (Okta, Entra, signed webhook) or a human task; dry-run first |
| Approval | low-risk actions run automatically | **every** action needs a human; unanswered = auto-denied after 30 min |
| Accounts | admin / analyst / viewer, password `phoenix-demo` | first visit creates the admin; 12+ char passwords, optional TOTP |
| Persistence | SQLite (same file) | SQLite, hash-chained audit, backups, retention |

> **Read [docs/PRODUCTION.md](docs/PRODUCTION.md) before pointing production mode at a real company.** PHOENIX X is a decision-support and response-orchestration system, not a replacement for your EDR/SIEM, and the live provider connectors were verified against mock servers, not real tenants (see *Honest limits* at the bottom).

## The dashboard (React + TypeScript)

The main interface lives in `frontend/` and is built with **React, TypeScript, Vite, Tailwind CSS, Framer Motion, Lucide, Recharts and React Flow**. The finished build is already in `public/`, so `node server/index.js` works with no extra step.

```bash
npm run ui:install   # once  (Windows: double-click build-ui.bat)
npm run ui:build     # type-check + build into public/
npm run ui:dev       # live reload on http://localhost:5173 (talks to the server on :3000)
```

* **Home** asks one question, "Are we safe?", shows a Safety score with Accounts, Servers, Cloud and Data sub-scores, and puts any decision that needs you right under the headline. Numbers, progress, the 12-step workflow, the attack map and agent messages are behind **See details**.
* **Five places only:** Home, Needs you (decisions), Activity (everything that came up, with the full story one tap away), Settings, and More tools (everything deeper, for experts).
* **One big button per situation** on Home: *Approve all* when decisions wait, *Watch it work* while Phoenix X is busy, *See what it did* afterwards, *Run a practice attack* when all is calm (demo mode) or *Connect your first app* (production mode).
* **Autopilot:** one switch on Home (and a first-visit welcome card) turns on the backend's full-autonomy mode, so Phoenix X handles everything it is allowed to. It still never deletes data, wipes or shuts down machines, and the hourly safety brake still applies.
* **Settings** controls how much Phoenix X does alone (Watch only, Balanced, Hands-free), the "always ask a person first" list, and the safety brake. These use the autonomy API described in `docs/AUTONOMY.md`.
* **Assistant:** the round button (bottom right) opens the built-in "Ask Phoenix X" chat.
* **Classic admin pages** (Connect a platform, Chat and alerts, Application resilience, Users, keys and backups) are still the original screens, served at `/classic/` and linked from Advanced and Settings. They share the same sign-in. Porting them to React is the next step if you want one uniform look.

## Quick start
Requires **Node.js 22.13+** (LTS). **No `npm install`: zero dependencies.** Full steps for Windows / Linux / Docker: [docs/AUTONOMY.md](docs/AUTONOMY.md) · [docs/SETUP.md](docs/SETUP.md).

```powershell
# Windows: unzip, then double-click start.bat   (or:)
cd phoenix-x
copy .env.example .env
node --disable-warning=ExperimentalWarning server\index.js
```
```bash
# macOS / Linux
cd phoenix-x && ./start.sh
# Docker
cp .env.example .env && docker compose up -d
```
Open **http://localhost:3000**. Demo mode: sign in `admin` / `phoenix-demo`. For production set `PHOENIX_MODE=production` in `.env`, restart, and create your administrator in the browser.

Tests: `npm test` (6 suites). 

## 3–5 minute judge demo
1. Sign in as **admin**. Click **⚡ LAUNCH CYBER ATTACK SIMULATION**.
2. Watch the orange *LIVE DEMO* banner narrate the attack (brute force → Moscow login → lateral move → token replay → 600 MB payroll download).
3. **SENTINEL** raises alerts → **COMMANDER** opens an incident → the 12-stage workflow lights up. Open **AI Agent Operations** to see the JSON messages between agents.
4. **INVESTIGATOR** builds the timeline + **Attack Graph** (click nodes for evidence). **ORACLE** flags the attacker IP (sample DB, or VirusTotal with a key).
5. **GUARDIAN** auto-executes low-risk actions (block IP, revoke sessions/token, restrict file) and **asks you** to approve *Disable account*. Click **Approve**.
6. **RECOVERY** checks backups, builds tasks. Open the incident → **Recovery** → *Complete all ready human tasks* → verification passes → **RESOLVED** → **Report** tab / download.
7. Try **Automated Response → Policy tester**: `shutdown_host` is refused even when “approved”.
8. Launch **Ransomware** to see a host with **no backup** (readiness gap) and **Benign travel** to see PHOENIX X *not* over-react.
Settings → *Workflow pace* slows the stages down for narration; *Autopilot* runs hands-free.

## Scenarios (all launchable in-app)
| # | Scenario | Shows |
|---|---|---|
| 1 | Credential compromise | brute force → success from unusual geo → token replay → bulk download; session revocation; approval-gated suspension |
| 2 | Ransomware (synthetic) | macro → C2 beacon → shadow-copy delete → mass rename; host isolation; backup verification; restore vs. no-backup rebuild; restricted wipe/shutdown listed manual-only |
| 3 | Insider threat | off-hours bulk download, self-granted admin, 450 MB upload to *unknown* IP (unknown ≠ malicious); approval-based restriction |
| 4 | Phishing | user-reported email statically analysed (**URLs never opened**), domains → intel, clickers found, ticket created |
| 5 | Cloud compromise | API enumeration, AdministratorAccess grant, key creation, public bucket, StopLogging attempt (restricted → human) |
| 6 | Benign: travelling employee | triaged to **monitor**, zero containment |

## Architecture
```
events ─► SENTINEL ─alert JSON─► COMMANDER (state machine, 12 stages)
 (generated | scenario | /api/ingest)    ├─► INVESTIGATOR → timeline, graph, confirmed vs hypothesis, ATT&CK
                                         ├─► ORACLE       → VirusTotal / local sample DB
                                         ├─► GUARDIAN     → plan → policy engine → approval → whitelisted executor
                                         └─► RECOVERY     → readiness, tasks, verification
 hash-chained audit log · evidence snapshots (SHA-256) · WebSocket fan-out · RBAC
```
Incident states: `DETECTED → TRIAGED → INVESTIGATING → ENRICHING → PLANNING → AWAITING_APPROVAL → CONTAINING → RECOVERING → VERIFYING → RESOLVED → CLOSED` (+ `MONITORING` for low-risk). Illegal transitions throw.

### Safety model
* **Three tiers** — *Automatic* (reversible, sandbox only) · *Approval required* (suspend account, isolate host, cloud/prod changes; admin only) · *Restricted* (delete/wipe/shutdown/security-control changes; **never executable**, even if approved).
* Policy is **re-checked at execution time**; unknown action types are denied by default; production assets can never be automatic.
* Agents have **no shell, no eval, no arbitrary scripts** — only the whitelisted functions in `guardian.js`. An LLM (optional) can only add prose; it cannot change structured facts or trigger actions.
* Every agent message is **schema-validated**; an invalid or failed agent degrades the incident but never crashes the pipeline (tested).
* **Honesty rules:** unknown indicators are never malicious; MITRE techniques are *evidence-supported* only when a rule directly observed the behaviour, otherwise *hypothesis*; a notification/ticket is “delivered/confirmed” only if the provider confirms, otherwise labelled *simulated*; rejected containment is reported as residual risk and blocks auto-resolve.
* Auth: scrypt passwords, HMAC-signed 8h tokens, role checks on every route, login rate-limit, input validation, CSP and security headers, binds to `127.0.0.1` by default.

## Connect your deployed apps (Vercel, Render, Heroku, Netlify, Railway, Cloudflare, GitHub, VPS, AWS …)
Open **Connect a Platform** in the dashboard: pick your platform, click *Create connection*, paste the URL it shows into that platform (a log drain, webhook or the SDK), and the page tells you when the first event arrives. Details and per-platform steps: [docs/PLATFORMS.md](docs/PLATFORMS.md). To host PHOENIX X itself (it needs a disk and HTTPS) see [docs/DEPLOY.md](docs/DEPLOY.md); `render.yaml`, `fly.toml` and `railway.json` are included.

* **Platform logs**: Vercel log drains, Heroku HTTPS drains, Cloudflare Logpush, nginx/Apache access logs, Render log streams (via a relay).
* **Platform events**: Vercel / Render / Netlify / Railway deploy and config webhooks, GitHub (leaked secrets, repo made public, deploy keys, branch-protection removal, force-push).
* **One-file SDK** (`/sdk/phoenix.js`): Express middleware, Next.js wrapper, login helpers; works on any host that runs Node.
* **Log shipper** (`scripts/ship-logs.js`): tails any file on a VPS with resume-after-restart.
* **Detections for web apps**: scanner paths, injection payloads, 4xx floods, WAF-block bursts, credential stuffing via HTTP 401s, secret leaks and risky config changes.

## AI autonomy: Watch / Balanced / Full AI
The AI blocks suspicious IPs, sessions, tokens and accounts **on its own** (Balanced), or also handles cautious actions (Full AI), or only recommends (Watch). You can unblock anything with one click, and the AI lifts its own blocks after a quiet period. Destructive actions never run in any mode. Details: [docs/AUTONOMY.md](docs/AUTONOMY.md).
Recovery is run by the AI too; critical steps that need a person show as numbered steps with **Done**, optional ones can be **Skipped**, approvals are **Allow / Disallow** buttons, keys rotate with one click, and a chat panel (bottom-right, with voice) takes commands like "block this ip" or "unblock sam" and answers questions; the AI resets passwords itself through Okta/Entra and verifies it, or gives you direct links and a Check button.
Connect GitHub, Heroku, Vercel, Render or Netlify with just a read-only API token: PHOENIX X pulls the logs itself (no drain or webhook needed).

## Production features
* **Persistence**: SQLite (`node:sqlite`, WAL). Events, incidents, audit chain, users, sessions, keys, suppressions, assets, tickets, notification outbox all survive restarts. An incident that was mid-workflow at a crash is flagged **Needs Attention** and *never silently resumed* (an admin resumes it deliberately).
* **Auth**: scrypt passwords, 12+ char policy, HttpOnly SameSite=Strict cookie sessions stored hashed, CSRF header, lockout (5 failures / 15 min), optional TOTP (required for admins with `PHOENIX_REQUIRE_ADMIN_TOTP=on`), session idle + absolute expiry, WebSocket origin check, user management UI, break-glass CLI (`npm run admin`).
* **Real data in**: per-source API keys (hashed, revocable, bound to one format; accepted as header, Basic password or URL token; optional HMAC/JWS signature verification) for **Okta, Entra, CloudTrail, Windows, syslog, CEF, Vercel, Heroku, Cloudflare, Netlify, Railway, Render, GitHub, nginx/Apache and generic JSON**. Dedupe, rate-limit, 1000 records/request.
* **Real containment out**: connectors for **Okta**, **Microsoft Entra (Graph)** and a generic **HMAC-signed webhook** (firewall, EDR, cloud). Dry-run by default; an action is "done" only when the provider confirms via read-back. Otherwise it becomes a **human task**.
* **Learns your users**: new users enter a *learning* state; a home country is learned only from clean logins (anti-poisoning), so day-one false positives are avoided. Geo/time anomalies are never judged on an unlearned user.
* **Tunable**: detection thresholds via env, suppression / known-good rules (reason required, optional expiry, audited).
* **Ops**: `/healthz`, `/readyz`, Prometheus `/metrics`, JSON logs, graceful shutdown, online backups (`npm run backup`), retention purge, Dockerfile + compose + Caddy (auto-HTTPS), systemd unit, GitHub Actions CI, optional built-in TLS.

## Documentation
[docs/AUTONOMY.md](docs/AUTONOMY.md) · [docs/SETUP.md](docs/SETUP.md) install (Windows/Linux/Docker) · [docs/DEPLOY.md](docs/DEPLOY.md) host it (Render/Fly/Railway/VPS) · [docs/PLATFORMS.md](docs/PLATFORMS.md) connect Vercel/Render/Heroku/… · [docs/PRODUCTION.md](docs/PRODUCTION.md) runbook, security model, hardening checklist · [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) log sources, connectors, tuning · [docs/API.md](docs/API.md) + [docs/openapi.yaml](docs/openapi.yaml) API reference

## Project layout
```
server/agents/   sentinel investigator oracle guardian recovery commander kb
server/core/     config db persist auth registry suppressions audit(hash chain) events generator schema ws(RFC6455) bus log
server/connectors/ okta entra webhook (GUARDIAN -> real world)
server/ingest/   normalizers (okta entra cloudtrail windows syslog cef)
scripts/         backup.js admin.js   deploy/ Caddyfile systemd
server/sim/      simulated enterprise (users, hosts, backups, cloud, firewall)
server/integrations/ notifications ticketing supabase
server/scenarios/    6 scenarios        public/ dashboard (12 pages, no build step)
db/schema.sql    Supabase schema + RLS   tests/  6 suites
```


## Honest limits (please read)
* **Platform integrations follow each vendor's published formats and are tested with fixtures and a local server, not against live Vercel/Render/Heroku/Netlify/Cloudflare/GitHub accounts.** Field names or plan requirements can differ from what I could confirm; the dashboard's "events received" indicator and *Send test event* button tell you immediately whether data is flowing. Render's native log stream needs a syslog relay (it cannot post HTTP directly); Netlify/Railway/Render webhooks carry deploy and config events, not request logs.
* **Autonomy is only as real as your connectors.** In Watch/Balanced/Full the AI decides, but a block changes a real system only through a configured connector (Okta, Entra, webhook) that confirms it; without one, production actions are recorded as dry-run/manual tasks. Full AI mode still never runs destructive actions, and auto-suspending an account can lock out a real user: protect VIP accounts and keep the circuit breaker low.
* **Voice** uses the browser's speech recognition (tested here only with a simulated recognizer, not a real microphone). The chat's free-form answers need an optional API key; otherwise it understands fixed commands and a built-in glossary.
* **Password reset** through Okta is confirmed by read-back; the Entra reset is trusted from the API's success response (Graph cannot read it back). Both were tested against mock servers only.
* **Pull collectors** (GitHub, Heroku, Vercel, Render, Netlify) are tested against mock servers only; Vercel request logs cannot be pulled (no public API). They read with your own read-only token and do not bypass any platform control.
* **Self-hosting configs** (`render.yaml`, `fly.toml`, `railway.json`, Dockerfile) were written to each platform's documented format but not deployed on those platforms from the build environment.
* **Live providers are verified against mock servers only.** The Okta, Entra and webhook connectors, and the Slack/Teams/Resend/Twilio/Jira/VirusTotal/Supabase adapters, follow the providers' documented APIs and are covered by tests against local mock HTTP servers, but were **not run against real tenants or accounts**. Always start with `PHOENIX_CONNECTOR_DRYRUN=on`, test on a non-critical account, then go live.
* **Detection is rules + simple statistics** (per-user z-scores, learned home geography), not a trained ML model. There is **no GeoIP database**: country comes from the log source (Okta/Entra provide it). Tune thresholds on your own traffic.
* **Single node.** SQLite on one server; no clustering or HA. Fine for a team/SMB scale (thousands of events per minute), not for a global enterprise firehose.
* **The AI is deterministic analysis**, with an optional LLM that may only add prose. It cannot change evidence or trigger actions.
* **Not a SIEM/EDR replacement and not independently pen-tested.** Review [docs/PRODUCTION.md](docs/PRODUCTION.md) (threat model, hardening checklist) before exposing it to a network.
* The original brief's React/Express/Socket.IO/LangGraph stack was replaced by a dependency-free Node implementation (the build sandbox blocks the npm registry); behaviour is the same, and it makes installation trivial.
