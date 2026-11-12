# Deploying PHOENIX X itself

PHOENIX X is a long-running server with a SQLite file. It needs: **a persistent disk**, **HTTPS**, and **a public URL** so your other platforms (Vercel, Render, Heroku, Cloudflare, GitHub …) can send it data.

| Host | Works? | Notes |
|---|---|---|
| **Render** (Docker web service + disk) | ✅ recommended | `render.yaml` is included. Disks need a paid instance type. |
| **Fly.io** (volume) | ✅ | `fly.toml` included. |
| **Railway** (volume at `/data`) | ✅ | `railway.json` included; add a volume mounted at `/data` in the dashboard. |
| **VPS** (DigitalOcean, Hetzner, EC2, Lightsail) | ✅ most control | Docker + Caddy profile gives automatic HTTPS. |
| **Vercel / Netlify / Cloudflare Workers** | ❌ cannot host it | Serverless: no persistent disk, no long-running process. They are *monitored by* PHOENIX, not hosts for it. |
| **Heroku** | ⚠️ not recommended | Ephemeral filesystem: the database would be wiped on every restart. |

> None of these deployments were run on the real platforms from the build environment; the configs follow each platform's documented format. Treat the first deploy as a checklist item and use `/healthz` to confirm.

## Render (recommended, ~5 minutes)
1. Push this folder to a GitHub repo.
2. Render Dashboard → **New → Blueprint** → select the repo. Render reads `render.yaml`.
3. After the first deploy, open the service → **Environment**, copy the generated `PHOENIX_SETUP_TOKEN`.
4. Open your `https://….onrender.com` URL → create the admin account (setup token + 12+ char password) and enrol 2FA.
5. **Connect a Platform** page → follow the wizard for each app you want to watch.

## Fly.io
```bash
fly launch --no-deploy --copy-config      # edit app name in fly.toml first
fly volumes create phoenix_data --size 1
fly secrets set PHOENIX_SETUP_TOKEN=$(openssl rand -hex 16)
fly deploy
```
## Railway
New project → Deploy from GitHub repo (Dockerfile is detected) → **Add Volume** mounted at `/data` → set variables `PHOENIX_MODE=production`, `PHOENIX_TRUST_PROXY=on`, `PHOENIX_SETUP_TOKEN=<random>` → Generate domain.
## VPS with automatic HTTPS
```bash
git clone <repo> && cd phoenix-x && cp .env.example .env
# in .env: PHOENIX_MODE=production, PHOENIX_SETUP_TOKEN=<random>, PHOENIX_DOMAIN=soc.example.com  (DNS A record -> server IP)
docker compose --profile tls up -d
```
## Environment variables you will actually set
`PHOENIX_MODE=production` · `PHOENIX_SETUP_TOKEN` · `PHOENIX_TRUST_PROXY=on` (behind any platform proxy) · `PHOENIX_REQUIRE_ADMIN_TOTP=on` · `PHOENIX_BACKUP_EVERY_HOURS=6`. Everything else is optional (see `.env.example`).

## After deploying
- `GET /healthz` → 200, `GET /readyz` → 200.
- Take a backup (**Settings → Back up database now**) and copy `/data/backups` somewhere off the host.
- Update = redeploy the same disk: the schema migrates automatically.
