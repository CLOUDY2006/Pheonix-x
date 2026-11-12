# PHOENIX X: Production runbook, security model & hardening

## 1. What production mode guarantees
* No simulated data, no attack-simulation button, no generator, no environment reset, no policy-tester endpoint.
* **Nothing runs without a human.** `autoContain` is off, autopilot cannot be enabled, and an unanswered approval is **auto-denied** after `PHOENIX_APPROVAL_TIMEOUT_MIN` (default 30). Fail-safe means "do nothing".
* **Unknown assets fail safe.** An asset not in the inventory is treated as production → approval required.
* **Honest status.** An action is `executed` only if the provider's read-back confirms it. Otherwise it is `dry_run`, `manual_required` or `failed`, and an incident with unapplied containment can never auto-resolve.
* **Restricted actions** (delete data, wipe/shutdown host, modify security controls, anything unknown) are refused at execution time regardless of approvals; they appear only as manual recommendations.
* **Recovery is human-owned.** PHOENIX never restores or reconnects hosts itself in production; it creates ordered tasks (confirm isolation → forensic capture → restore/rebuild → clean-scan → reconnect) that people attest.
* **Tamper-evident audit.** Every decision is SHA-256 hash-chained; `/readyz` fails if the chain breaks, and startup logs a loud error.

## 2. Roles
| Role | Can |
|---|---|
| viewer | read incidents, events, audit |
| analyst | + notes, assign, status, complete recovery tasks, intel lookup |
| admin | + **approve/reject containment**, users, ingest keys, suppressions, assets, settings, backup, resume interrupted incidents |

## 3. Threat model (what it defends against / what it does not)
| Threat | Control |
|---|---|
| Stolen browser session | HttpOnly + SameSite=Strict + Secure cookie; CSRF header; hashed server-side sessions; idle (60 min) + absolute (8 h) expiry; password change revokes all sessions |
| Password guessing | scrypt, 12+ chars, per-account (5/15 min) and per-IP lockout, constant-ish-time unknown-user path, optional TOTP |
| Log-injection driving harmful containment | ingest needs a per-source key; Guardian only runs whitelisted functions; approval gate; unknown→approval; restricted tier hard-blocked; every action is audited |
| Attacker poisons baselines | learning only from clean logins; thresholds per environment |
| Attacker with DB write access | audit chain breaks (detected, not prevented). Protect the file (OS permissions, disk encryption). |
| Cross-site WebSocket hijack | Origin check + cookie auth |
| DoS | per-IP and per-key rate limits, body size caps, request timeouts. Put a reverse proxy/WAF in front for more. |
**Not covered:** a compromised server OS, a malicious admin (they can approve actions; the audit trail records it), supply chain of Node itself, and any weakness in an upstream provider.

## 4. Hardening checklist
- [ ] TLS: Caddy profile, nginx, or `PHOENIX_TLS_CERT/KEY`. Never expose plain HTTP.
- [ ] `PHOENIX_TRUST_PROXY=on` only when a proxy you control sets `X-Forwarded-For`.
- [ ] `PHOENIX_SETUP_TOKEN` set before first start if reachable from a network.
- [ ] `PHOENIX_REQUIRE_ADMIN_TOTP=on`.
- [ ] Bind `HOST=127.0.0.1` and publish only through the proxy.
- [ ] Run as a dedicated non-root user; `data/` mode 700 (the systemd unit and Dockerfile already do this).
- [ ] Backups copied off-host and a **restore test** done at least once.
- [ ] Ingest keys: one per source; revoke when a source is retired. A hook URL (`/api/hook/<key>`) carries the key in the path, so keep it out of screenshots and tickets and set a **signing secret** wherever the platform supports one (Vercel, GitHub, Netlify).
- [ ] Connector credentials: least privilege (Okta token limited to user lifecycle/sessions; Entra app with only `User.ReadWrite.All`), stored only in `.env` (mode 600).
- [ ] Alert on `/metrics`: `phoenix_audit_chain_ok == 0`, `phoenix_pending_approvals > 0 for 10m`, `up == 0`.

## 5. Day-2 operations
**Backups**: `npm run backup` (online-safe snapshot to `data/backups`, 14-day pruning) or `PHOENIX_BACKUP_EVERY_HOURS`. **Restore**: stop the server, replace `data/phoenix.db` with a backup file (delete `phoenix.db-wal`/`-shm`), start; check `/readyz`.
**Upgrade**: stop, back up, unzip the new version over the old (keep `.env` and `data/`), start. Schema migrations run automatically (`PRAGMA user_version`).
**Restart behaviour**: incidents mid-workflow become *Needs Attention* with a note; pending approvals are cancelled; an admin reviews and presses **Resume** (or handles manually).
**Retention**: raw events older than `PHOENIX_RETENTION_DAYS` are purged every 6 h; incidents and the audit log are kept.
**Locked out / lost 2FA**: `npm run admin -- reset-password|disable-2fa|create-admin ...` on the server.
**Break-glass for containment**: if a connector misbehaves set `PHOENIX_CONNECTOR_IDENTITY=none` and restart; GUARDIAN then produces human tasks only.

## 6. Going live with a connector (recommended path)
1. Ship real logs for a week with connectors `none`. Review incidents, tune thresholds, add suppressions.
2. Switch the identity connector to `okta`/`entra` with `PHOENIX_CONNECTOR_DRYRUN=on`. Approve actions and confirm the **DRY-RUN** results read sensibly.
3. Test on a throw-away user in your IdP with `DRYRUN=off`; confirm suspension *and* re-enable (rollback) work.
4. Only then enable it broadly. Keep approvals on; do not enable `PHOENIX_AUTO_CONTAIN` until you trust the detections.

## 6b. Capacity guide (single node)
Comfortable: a few thousand events/min, tens of thousands of incidents. Events are held in memory (last 20k) and persisted in batches; the database is trimmed by retention. If you need more, shard by log source or run a collector in front that pre-filters (failed logins, privilege changes, cloud config changes).
