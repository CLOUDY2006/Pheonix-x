# Application Resilience

**Know what is affected. Know how to recover. Prove that recovery worked.**

Same six agents, new responsibilities: SENTINEL detects; INVESTIGATOR maps dependencies and blast radius (`inc.blast`); ORACLE matches history (`inc.similar`); GUARDIAN builds reversible plans; RECOVERY rehearses and executes; COMMANDER enforces approvals and runs verification.

## 1. Dependency map
Connect providers on **Connect a Platform** with read-only tokens (Vercel, Render, Netlify, Heroku, Supabase, GitHub), then **Discover**. PHOENIX X reads service/project names, repositories and environment-variable **names**, plus the host of URL-valued variables. **Values are never stored.**
Edges say "A depends on B" and carry a confidence:
- **verified**: reported by a provider API, or a URL host matched a known service (e.g. `https://<ref>.supabase.co`).
- **declared**: added by an admin.
- **inferred**: guessed from a variable name (`SUPABASE_*`, `STRIPE_*`, `DATABASE_URL` …). Always labelled; a path is only as certain as its weakest edge, but a verified route beats a shorter inferred one.

## 2. Blast radius
Given a compromised item: everything that depends on it, what a compromised secret can reach, secrets a compromised repo/service could read, which services need a redeploy.

## 3. Recovery rehearsal (read-only)
Choose a scenario (credential / repo / provider takeover). Output: affected items, recovery plan, readiness checks, missing requirements, estimated steps/time and interruption, a 0-100 score and a verdict (READY / PARTIALLY READY / NOT READY). Checks: dependencies known, provider access, replacement-credential path, redeploy capability, **backup exists** (Supabase: read from the Management API; others: admin attestation < 30 days, labelled unverified), verification coverage, old-credential test. A missing backup or no verification checks is **blocking**.

## 4. Safe recovery execution
Preview (what changes, affected services, risks, reversal, verification) → **admin approves** → execute → auto-verify.
- PHOENIX X itself performs **redeploy/restart** (Render, Vercel, Netlify, Heroku). Before acting it records the previous deployment so the step can be **rolled back**.
- A connection needs **write access** switched on, and live calls need `PHOENIX_CONNECTOR_DRYRUN=off`. Otherwise execution is a dry-run (logged, nothing changed).
- Revoking the compromised credential and setting new secret values stay with a human (direct links, Done button): PHOENIX X never handles new secrets. Containment steps cannot be skipped.

## 5. Verification engine
Real HTTP probes you define: endpoint health (status/body/latency), metric thresholds (e.g. error rate), **old credential rejected**, **new credential works**. Credentials are stored encrypted. SSRF guard: public http(s) targets only (`PHOENIX_VERIFY_ALLOW_PRIVATE=1` to allow internal). Reports are hashed (SHA-256) and stored.

## 6. Incident memory
Resolved incidents are stored (findings, timeline, actions, approvals, recovery, verification, evidence hash). New incidents are matched by signature similarity and the earlier procedure is suggested. `GET /api/resilience/memory/:id` returns a bundle with stored vs recomputed hash.

## 7. Leak response, posture scan, game day, briefings
- **Leaked-secret response:** a GitHub secret-scanning alert is matched to your variables (e.g. a Stripe key → `STRIPE_*`), the blast radius is computed and a recovery plan **preview** is prepared (`inc.leak`). An admin still approves it.
- **Posture scan** (`POST /api/resilience/posture`, chat: *security check*): private-looking `NEXT_PUBLIC_/VITE_…` variables, Supabase tables without row-level security (reads `pg_tables` via the Management API), GitHub default branch unprotected, secret scanning off.
- **Game day** (`POST /api/resilience/gameday`, chat: *game day*): rehearses every suggested scenario, keeps a score history, alerts channels when readiness drops. Automatic with `PHOENIX_GAMEDAY_HOURS=168`.
- **Briefing** (`GET /api/incidents/:id/briefing`, chat: *brief me*): what happened, why it matters, what is done, what to do now. Deterministic: it only restates the incident record.

## Honest limits
Provider endpoints are written from public API docs and tested against mock servers only: try with a read-only token first, and expect to adjust a field. Vercel/Netlify rollback semantics differ by plan. Credential rotation itself is not automated. Backup *restore* is not automated; only existence is checked. Inferred links can be wrong.

Chat: `discover`, `what depends on supabase`, `rehearse supabase`, `are we ready`, `verify recovery`, `similar incidents`.
