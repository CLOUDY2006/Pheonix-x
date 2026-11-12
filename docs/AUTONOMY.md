# AI autonomy, unblock and self-recovery

PHOENIX X can act on its own. **You decide how much**, per deployment, and change it any time (Response or Settings page, admin only; every change is audited).

| Mode | What the AI does alone | What waits for a human |
|---|---|---|
| **Watch** (production default) | Detects, investigates, correlates, drafts the containment plan and report | Every action |
| **Balanced** (demo default) | Blocks IPs, revokes sessions/tokens, restricts a resource, **suspends a suspicious account** | Isolate host, cloud-policy detach, make bucket private, production assets |
| **Full AI** | Everything above plus the cautious actions; lifts its own blocks after a quiet period | Protected entities and internal IPs |

Set the start-up mode with `PHOENIX_AUTONOMY=watch|balanced|full`. A change made in the UI is stored in the database and wins after a restart.

## Always true, in every mode
- **Restricted actions never run**: delete data, shut down or wipe a host, change a security control. Not even "approved". This is a hard rule, not a setting.
- **Protected entities** (users, IPs, hosts, resources; plus all private/internal IPs) always need a human. Manage them on the Response page.
- **Circuit breaker**: at most `PHOENIX_AI_ACTION_BUDGET` (default 25) automatic actions per rolling hour. After that the AI asks a human and the audit log records it.
- **Everything is audited** (hash-chained): `AI_AUTO_ACTION` with the rationale, `ACTION_UNBLOCKED`, `AI_SELF_RECOVERY`, `AUTONOMY_CHANGED`.
- In production, automatic actions only change a real system through a connector that confirms the change (see PRODUCTION.md). With connectors in dry-run the action is recorded as `dry_run`, not executed.

## Unblock
The Response page lists **Active blocks**. Analysts can **Unblock**; admins can also **Unblock & trust** (adds a permanent protected entry so the AI never blocks it again). A plain unblock gives a 24 h hold-off in which the AI will not re-apply the block by itself.
API: `GET /api/containments`, `POST /api/actions/:id/undo {trust?, reason?}`.

## Self-recovery
Blocks made by the AI carry a lifetime (IP block, resource restriction, account suspension, host isolation: 24 h). A sweeper (`PHOENIX_SWEEP_SEC`, default 60) lifts an expired block only if the current mode allows it (Balanced: IPs and resources; Full: also accounts and hosts) and **no new related alert** arrived since; otherwise the lifetime is extended. Cloud-policy and bucket changes are never lifted automatically. Watch mode never lifts anything. Recovery of data from backups stays a human-attested task in production.

## Pull collectors ("no drains needed")
Connect page → "Connect with an API token". PHOENIX X polls GitHub, Heroku, Vercel, Render and Netlify with a **read-only token you create** (default every 120 s). Tokens are AES-256-GCM encrypted (`PHOENIX_SECRET_KEY`, or an auto-generated `data/.secret`; back it up with the database). First connect records existing items as a baseline so old items do not alert. This uses only your own credentials and the platforms' documented read APIs; it does not bypass any platform logging, rate limit or access control.
Limits: Vercel request logs have no pull API (use a Log Drain or the SDK); GitHub secret-scanning needs the right plan/scope; provider API shapes are verified against mock servers only, so test with a read-only token first. Polling API base URLs can be overridden for testing with `PHOENIX_API_GITHUB|HEROKU|VERCEL|RENDER|NETLIFY`.
API (admin): `GET/POST /api/collectors`, `POST /api/collectors/:id/run|enable|remove`.

## Recovery: the AI does it, you do only what needs you
After containment the AI builds a recovery plan and runs every step it can. Steps that only a person can do (rebuild a host, reset a password at your identity provider, rotate a leaked secret) appear in **Recovery Centre** as numbered, plain-language steps with a **Done** button. The AI continues the moment you press it.
- **Optional** steps (evidence snapshot, mailbox review) have a **Skip** button. **Required** steps cannot be skipped.
- Steps that lift a block (re-enable an account, reconnect an isolated host) are done by the AI. In **Watch** mode they show **Allow / Disallow**: press Allow and the AI does it; Disallow leaves the block in place.
- Anything the AI does can be reverted by a human (Active blocks → Unblock).
- **Approvals** are two buttons everywhere: **Allow** (the AI then executes it) or **Disallow**. A yellow bar on every page shows how many are waiting, with **Allow all**.
- **Key rotation is one button**: Connect page or Settings → ingest keys → 🔑 Rotate (new secret shown once, old one dies). Collector tokens can be replaced via `POST /api/collectors/:id/token`.

## Recovery in the fewest steps
- The AI **forces the password reset itself** through Okta or Microsoft Entra (`force_password_reset`; Okta is confirmed by reading the user back as PASSWORD_EXPIRED). When that works there is **no human step** for that user, and the AI re-enables the suspended account right away.
- If the AI can't (no connector, dry-run, provider error) you get **one** step with direct buttons to your identity provider (Okta admin / Entra / Google Workspace), then **Check it**: the AI asks Okta/Entra whether the password really changed and continues by itself. It also re-checks every minute in the background. Without a connector it can't verify, so you press Done.
- Hosts: **one** human step (rebuild from a verified backup, or scan), then the AI reconnects the host. Secret/cloud-key rotation: **one** step with a link to the right token page (GitHub, Vercel, Render, Heroku, Netlify, Cloudflare, AWS, Google Cloud, Azure). Vendor URLs can change; they are shortcuts.
- Rotating PHOENIX's own keys: **Rotate** per key or **Rotate all** (Connect page, Settings, or chat). Collector tokens: **New token** button next to each connection, with a link to the platform's token page.

## Chat assistant (bottom-right) and voice
A compact bar that opens into a chat. Commands are understood by fixed rules (nothing leaves your server) and run the same actions as the buttons, with the same role checks and audit trail. It asks follow-up questions when something is ambiguous, and confirms risky ones (suspend an account, isolate a host, block an internal IP, rotate all keys).
- **Do things:** `block 203.0.113.9` · `block this ip` (uses the IP from the conversation or the latest incident) · `disable bob` · `reset password for bob` · `revoke sessions for bob` · `isolate ws-bob-01` · `unblock sam` · `trust sam` · `allow` / `disallow` · `done` / `skip` / `check` · `set mode to full` · `protect ceo@acme.com` · `rotate key vercel` · `rotate all keys`.
- **Ask things:** `status` · `what's blocked?` · `what needs me?` · `why was sam blocked?` · `activity for 203.0.113.9` · `who is bob?` · `list incidents` · `how safe are we?` · `what is ransomware / phishing / MFA / SQL injection …?` · `explain INC-1001`.
- **Anything else:** if you set `ANTHROPIC_API_KEY` and `PHOENIX_CHAT_LLM=on`, other questions are answered by the model from a short state summary (incident titles, counts). It can explain and suggest commands but never executes anything. Off by default.
- **Voice:** press 🎤 and speak a command; it is run like typed text. 🔊 reads answers aloud. This uses the browser's built-in speech features (Chrome, Edge, Safari). Chrome and Edge send the audio to the browser vendor's speech service, so use typing if that is a concern. Needs HTTPS or localhost and microphone permission. Risky commands still ask you to say "yes".
Manual actions through chat or `POST /api/manual {type,target}` are executed by the same guarded path (connectors, dry-run, audit) and appear under Active blocks so they can be reverted. Protected entities cannot be blocked.
