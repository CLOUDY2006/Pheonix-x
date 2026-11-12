# Integrations

## 1. Log ingestion
> Deployment platforms (Vercel, Render, Heroku, Netlify, Railway, Cloudflare, GitHub, VPS, AWS) have a guided wizard and their own page: [PLATFORMS.md](PLATFORMS.md). A key may also be sent as `/api/hook/<key>` (URL) or as an HTTP Basic password, and signed webhooks can be verified with a per-key signing secret.

Create a key in **Settings → Ingest keys** (shown once; stored hashed). A key is **bound to one format**. Send with header `x-api-key`. Max 1000 records / 5 MB per request, 300 requests/min per key. Re-sending the same Okta `uuid` / Entra `id` / CloudTrail `eventID` is de-duplicated.

| Format (key) | Endpoint | Body | Notes |
|---|---|---|---|
| `okta` | `POST /api/ingest/okta` | JSON array from `GET /api/v1/logs` | session start/failed, MFA, lockout, privilege grants; country/city from Okta context |
| `entra` | `POST /api/ingest/entra` | `{ "value": [...] }` from Graph `/auditLogs/signIns` | error code 0 = success; location included |
| `cloudtrail` | `POST /api/ingest/cloudtrail` | `{ "Records": [...] }` | IAM policy attach, access-key create, bucket ACL/policy, StopLogging/DeleteTrail, ConsoleLogin |
| `windows` | `POST /api/ingest/windows` | JSON array with `EventID`, `Computer`, `EventData` | 4624, 4625, 4720, 4728/4732/4756, 4688, 1102/104 |
| `syslog` | `POST /api/ingest/syslog` | `text/plain` lines or `{ "lines": [...] }` | sshd `Failed/Accepted password/publickey` |
| `cef` | `POST /api/ingest/cef` | lines of ArcSight CEF | login success/failure from the event name |
| `vercel` `vercel-webhook` `render` `render-webhook` `heroku` `netlify` `railway` `cloudflare` `github` `nginx` | `POST /api/ingest/<format>` or `/api/hook/<key>` | vendor-native bodies (JSON, NDJSON, gzip, Logplex, access-log lines) | see [PLATFORMS.md](PLATFORMS.md) |
| `generic` | `POST /api/ingest` | `{ "events": [ {source,type,user,ip,...} ] }` | PHOENIX native schema |

PHOENIX native schema: `source` (authentication, application, system, network, api, file, cloud), `type` (login_success, login_failed, privilege_change, mass_download, file_rename, beacon, ...), optional `ts`, `user`, `ip`, `host`, `geo` (`{country, city}`), `resource`, `outcome`, `bytes`, `count`, `details`.

**Shipping examples**
```bash
# Okta: pull the last 5 minutes every 5 min (cron)
curl -s -H "Authorization: SSWS $OKTA_TOKEN" "https://ORG.okta.com/api/v1/logs?since=$(date -u -d '-5 min' +%FT%TZ)" \
 | curl -s -X POST https://soc.example.com/api/ingest/okta -H "x-api-key: $PHX_KEY" -H 'content-type: application/json' --data-binary @-
# Linux auth log (tail + send in batches)
tail -n 200 /var/log/auth.log | curl -s -X POST https://soc.example.com/api/ingest/syslog -H "x-api-key: $PHX_KEY" -H 'content-type: text/plain' --data-binary @-
# AWS: CloudTrail -> S3 -> Lambda/cron posts {"Records":[...]} files to /api/ingest/cloudtrail
```
Any log shipper (Vector, Fluent Bit, Logstash, Windows Event Forwarding + a script) can post JSON.

## 2. Detection tuning
Environment variables (restart to apply): `PHOENIX_TH_BRUTE` (failed logins before alert), `PHOENIX_TH_SPRAY_USERS`, `PHOENIX_TH_MASS_FILES`, `PHOENIX_TH_MASS_MB`, `PHOENIX_TH_EXFIL_MB`, `PHOENIX_TH_RENAMES`, `PHOENIX_BUSINESS_HOURS` (e.g. `9-19`), `PHOENIX_UTC_OFFSET_HOURS` (e.g. `5.5`), `PHOENIX_BASELINE_LOGINS`.
**Known-good (suppression):** Settings → Suppressions: rule + (user | ip | host) + **mandatory reason** + optional expiry. Example: the vulnerability scanner `10.0.4.9` triggers `R-BRUTE` → suppress rule `R-BRUTE`, ip `10.0.4.9`, reason "Nessus weekly scan, ticket SEC-114".
**Asset inventory:** tell PHOENIX which assets are production/critical (Settings → Asset inventory) and record backups (host, id, time, verified, immutable) so recovery readiness is real.

## 3. Containment connectors
| Domain | Actions | Adapters |
|---|---|---|
| identity | `disable_account`, `revoke_sessions`, `revoke_token` | `okta`, `entra`, `webhook` |
| network | `block_ip` | `webhook` |
| endpoint | `isolate_host` | `webhook` |
| data | `restrict_resource` | `webhook` |
| cloud | `detach_cloud_policy`, `make_bucket_private` | `webhook` |

`PHOENIX_CONNECTOR_<DOMAIN>=none|okta|entra|webhook`. With `none`, approved actions become **MANUAL REQUIRED** and a recovery task asks a human to apply and confirm it.
**Okta** needs `OKTA_URL`, `OKTA_API_TOKEN`: suspends via `/lifecycle/suspend`, reads the user back and requires `SUSPENDED`; rollback = `/lifecycle/unsuspend`. **Entra** needs tenant/client id/secret (client-credentials, Graph application permission `User.ReadWrite.All`): sets `accountEnabled=false`, calls `revokeSignInSessions`, reads back.
**Webhook**: `POST` JSON `{kind:"execute"|"rollback", action, target, incidentId, requestedBy, actionId, ts}` with headers `Idempotency-Key: <actionId>:<kind>` and `X-Phoenix-Signature: sha256=HMAC(PHOENIX_WEBHOOK_SECRET, body)`. Reply `2xx` (optionally `{"confirmed":false}` to refuse, `{"detail":"..."}`). Verify the signature on your side; use the idempotency key to make retries safe. Per-domain URLs: `PHOENIX_WEBHOOK_URL_NETWORK`, `_ENDPOINT`, `_IDENTITY`, `_DATA`, `_CLOUD`; fallback `PHOENIX_WEBHOOK_URL`. A small receiver that calls your firewall/EDR API is ~30 lines in any language.
Dry-run (`PHOENIX_CONNECTOR_DRYRUN=on`, default) never calls the provider.

## 4. Notifications, tickets, threat intel, LLM
Set the variables in `.env.example` (Slack/Teams webhooks, Resend email, Twilio SMS, Jira Cloud, VirusTotal, Anthropic). Each integration is shown honestly in Settings: unconfigured ones say *not configured*; a notification/ticket is marked delivered/confirmed only when the provider responds successfully.

## 5. Supabase (optional)
Run `db/schema.sql` in a Supabase project, set `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` (server-side only) to mirror events/incidents/audit there for external dashboards. The primary store is the local SQLite file either way.
