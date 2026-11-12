# Chat & Alerts (Telegram · Slack · Discord · Email)

Open **Chat & Alerts** in the app (admin). Alerts go out to every connected channel; commands come in from Telegram, Slack and Discord.

## What chat can and cannot do
| From chat (works) | Stays in the app (refused in chat, with a link) |
|---|---|
| status, what's blocked, explain, **brief me** | Allow / Disallow of approvals |
| block / unblock an IP or user, disable user, isolate host | rotating keys, changing the AI mode |
| rehearse, verify recovery, security check, game day | marking recovery steps done/skipped, trust lists |
| what depends on X, similar incidents | executing or approving recovery plans, discovery |
Chat users are **capped at analyst** (or viewer) rights, whatever they ask.

## Safety
- Nobody is obeyed until **paired**: admin presses *Pair a person*, then the person sends `link CODE` (one-time, 15 min) from their own chat. Strangers get a refusal that shows their ID.
- Slack: HMAC signing-secret check + 5-minute replay window. Discord: Ed25519 signature check. Telegram: long polling, private chats only (no public URL needed).
- Tokens/secrets are AES-256-GCM encrypted and never returned. Webhook URLs are restricted to slack.com / discord.com.
- Every command, refusal and failed pairing is in the audit log (actor `telegram:<id>`).
- Email is **alerts only** (sender addresses can be forged).

## Set-up
- **Telegram:** talk to @BotFather → `/newbot` → paste the token → *Pair a person* → send `link CODE` to your bot.
- **Slack:** create an app → slash command `/phoenix` with the Request URL shown on the page → copy *Signing Secret* → (optional) incoming webhook for alerts. Use `/phoenix status`, `/phoenix link CODE`.
- **Discord:** create an application → command `/phoenix` with one string option `text` → set *Interactions Endpoint URL* → paste the *Public Key* → (optional) channel webhook for alerts.
- **Email:** a Resend API key, from address, recipients.
- Slack/Discord need PHOENIX X on a public https URL; set `PHOENIX_PUBLIC_URL` so alerts link back to the app.

## Alerts
New incidents at or above the channel's minimum severity (with a plain-language briefing), approvals waiting (link to the app), resolutions, leaked-secret findings and game-day readiness drops. One alert per incident, not one per update.

Honest limits: tested against mock Telegram/Slack/Discord/Resend servers, not live ones. Slack/Discord setup in their consoles is manual.
