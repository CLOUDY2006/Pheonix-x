# API reference

JSON over HTTP. Browser sessions use the `phx_session` HttpOnly cookie **plus** header `x-csrf-token` (value from `/api/auth/login` or `/api/auth/me`) on every non-GET. Scripts can instead send `Authorization: Bearer <token>` (the `token` returned by login; no CSRF header needed). Log shippers use `x-api-key`. Machine-readable spec: [openapi.yaml](openapi.yaml). Errors are `{ "error": "message" }` with 400/401/403/404/409/413/422/429/503.

## Public
| Method & path | Purpose |
|---|---|
| `GET /healthz` | liveness: `{ok, uptimeSec, mode}` |
| `GET /readyz` | readiness: 200 if DB reachable **and** audit chain verifies, else 503 |
| `GET /metrics` | Prometheus text. Needs `Authorization: Bearer $PHOENIX_METRICS_TOKEN` or a login |
| `GET /api/auth/status` | `{mode, setupRequired, setupTokenRequired, demo}` |
| `POST /api/auth/setup` `{username,password,setupToken?}` | first-run admin creation (one-shot) → logs in |
| `POST /api/auth/login` `{username,password,totp?}` | → `{user,role,csrf,token}` + cookie. 401 `{totpRequired:true}` if a code is needed. 429 when locked out |

## Account (any signed-in user)
`POST /api/auth/logout` · `GET /api/auth/me` · `POST /api/auth/password {current,next}` · `POST /api/auth/totp/begin` → `{secret,uri}` · `POST /api/auth/totp/confirm {code}`

## Operations
| Method & path | Role | Purpose |
|---|---|---|
| `GET /api/state` | viewer | full dashboard snapshot |
| `GET /api/incidents/:id` | viewer | incident + audit trail |
| `GET /api/incidents/:id/report.md` · `report.json` | viewer | report / evidence bundle |
| `POST /api/incidents/:id/notes {text}` · `/assign {analyst}` · `/status {status}` | analyst | workflow |
| `POST /api/incidents/:id/verify` · `/tasks/:tid/complete` · `/tasks/complete-all` | analyst | recovery tasks / re-verify |
| `POST /api/incidents/:id/resume` | admin | resume an incident interrupted by a restart |
| `POST /api/actions/:id/approve` · `/reject` `{comment}` | **admin** | approve/reject a containment action |
| `GET /api/events?limit=` · `/api/audit?limit=` · `/api/audit/verify` · `/api/kb?q=` | viewer | data |
| `POST /api/intel/lookup {type: ip\|domain\|hash, value}` | analyst | indicator check |
| `GET /api/suppressions` | viewer | list |
| `GET /api/assets` | viewer | asset inventory |

## Administration (admin)
| Method & path | Body |
|---|---|
| `GET/POST /api/users` | `{username,password,role,mustChange?}` |
| `POST /api/users/:name/update` | `{role?,disabled?,password?}` |
| `POST /api/users/:name/delete` · `/totp-reset` | |
| `GET/POST /api/keys` · `POST /api/keys/:id/revoke` | `{name,format,signingSecret?,verifyToken?}` → plaintext `key` returned **once** |
| `POST /api/suppressions` · `/api/suppressions/:id/remove` | `{rule,user?,ip?,host?,reason,expiresInHours?}` |
| `POST /api/assets/:kind/:name` (`kind` = host\|user\|resource) | `{env: production\|sandbox, criticality, owner, ...}` |
| `POST /api/assets/backups` | `{host,id,ts,verified,immutable,sizeGB}` |
| `POST /api/settings` | `{paceMs?, autoContain?, approvalTimeoutMin?}` (+ `autopilot`, `generator` in demo) |
| `POST /api/admin/backup` | → `{file}` online-safe DB snapshot |
| `GET /api/platforms` | connection wizard catalog |
| `POST /api/keys/:id/test` | inject a harmless test event for a connection (admin) |

## Autonomy, unblock, collectors
| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/autonomy` | viewer | mode, budget, protected entities |
| `POST /api/autonomy` | admin | `{mode: watch\|balanced\|full}` |
| `POST /api/protected`, `POST /api/protected/:id/remove` | admin | `{kind,value,reason,hours?}` |
| `GET /api/containments` | viewer | active, undoable blocks |
| `POST /api/actions/:id/undo` | analyst | `{trust?,reason?}`; `trust` needs admin |
| `POST /api/manual` | analyst | `{type: block_ip\|disable_account\|revoke_sessions\|force_password_reset\|isolate_host\|restrict_resource, target}` |
| `POST /api/incidents/:id/tasks/:tid/check` | analyst | AI verifies a human step with the provider |
| `POST /api/keys/rotate-all` | admin | rotates every active ingest key |
| `POST /api/chat` | viewer | `{message}` → `{reply, choices?}` (actions enforce the role needed) |
| `POST /api/incidents/:id/tasks/:tid/skip` | analyst | optional steps, or Disallow on a gated AI step |
| `POST /api/keys/:id/rotate` | admin | new key returned once; old key disabled |
| `POST /api/collectors/:id/token` | admin | replace a collector's token |
| `GET/POST /api/collectors` | admin | `{platform,token,config,name?,intervalSec?}`; token never returned |
| `POST /api/collectors/:id/run\|enable\|remove` | admin | |

## Ingestion (`x-api-key` bound to a format, or an admin session)
`POST /api/ingest` (key's own format; `{events:[…]}` for generic) · `POST /api/ingest/{generic|okta|entra|cloudtrail|windows|syslog|cef|vercel|vercel-webhook|render|render-webhook|heroku|netlify|railway|cloudflare|github|nginx}` · `POST|GET /api/hook/<key>` (URL-token form; format = the key's; GET is a reachability check and answers Vercel's `x-vercel-verify` handshake) → `{accepted, duplicates, ignored, rejected:[{index,error}]}`. Key via `x-api-key`, HTTP Basic password, or the URL. Bodies may be JSON, NDJSON, gzip, `text/plain` lines or Heroku `application/logplex-1`. Optional per-key signing-secret verification: Vercel `x-vercel-signature` (HMAC-SHA1), GitHub `x-hub-signature-256`, Netlify `x-webhook-signature` (JWS HS256). Formats and examples: [INTEGRATIONS.md](INTEGRATIONS.md).

## Demo-mode only (403 in production)
`POST /api/scenarios/:id/launch {autopilot?, reset?}` (`credential-compromise`, `ransomware`, `insider-threat`, `phishing`, `cloud-compromise`, `benign-travel`, `signature`) · `POST /api/reset` · `POST /api/guardian/execute {type,target,approve}` (policy tester).

## Application resilience (`/api/resilience/*`)
`GET graph` · `POST discover` (admin) · `POST graph {node|edge}` / `graph/remove` (admin) · `POST blast {target}` (analyst) · `GET scenarios` · `POST rehearse {scenario: credential|repo|provider, target}` (analyst) · `GET rehearsals/:id` · `POST backup {node,note}` (admin, attest a verified backup)
`GET plans` · `POST plans {rehearsalId | scenario,target}` → preview · `POST plans/:id/approve|reject|execute` (admin) · `POST plans/:id/steps/:sid {state: done|skipped}` (admin) · `POST plans/:id/steps/:sid/undo` (admin, rollback)
`GET checks` · `POST checks {name,type,config,secret?}` (admin) · `POST checks/:id/remove` · `POST verify` (analyst) · `GET memory` · `GET memory/:incidentId` (evidence bundle with integrity hashes) · `GET /api/incidents/:id/similar` · `POST /api/collectors/:id/write {enabled}` (admin; lets PHOENIX X redeploy that service).

## Chat channels (`/api/channels*`, admin)
`GET /api/channels` · `POST` create `{kind: telegram|slack|discord|email, name, config, minSeverity, role}` · `POST :id/pair` (one-time code) · `POST :id/allow {user,on}` · `POST :id/settings {role,minSeverity}` · `POST :id/test|enable|remove`.
Public, signature-verified inbound: `POST /api/channels/slack/:id` (HMAC), `POST /api/channels/discord/:id` (Ed25519). Telegram uses polling.
Also: `POST|GET /api/resilience/posture`, `POST|GET /api/resilience/gameday`, `GET /api/incidents/:id/briefing`.

## WebSocket `/ws`
Same-origin only (Origin checked), cookie-authenticated. Messages `{type,data}`: `hello`, `event`, `alert`, `incident`, `agent_msg`, `agents`, `approval`, `audit`, `scenario`, `notification`, `metrics`, `reset`. Sessions are re-validated every minute; revoked sessions are disconnected.
