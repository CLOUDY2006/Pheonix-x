# PHOENIX X: Setup guide

Three ways to run it. All need **no `npm install`**.

## A. Windows (easiest)
1. Install **Node.js 22.13 or newer** (LTS "Windows Installer": https://nodejs.org). Re-open the terminal and check: `node --version` → `v22.13` or higher.
2. Unzip `phoenix-x.zip` (for example to `C:\phoenix-x`).
3. Double-click **`start.bat`**. It creates `.env` and the `data` folder, then opens http://localhost:3000.
4. **Demo mode** (default): sign in with `admin` / `phoenix-demo` and click **LAUNCH CYBER ATTACK SIMULATION**.
5. **Production mode**: open `.env` in Notepad, set `PHOENIX_MODE=production`, save, close the black window and run `start.bat` again. The first page asks you to create the administrator account.

Manual start (same thing): `node --disable-warning=ExperimentalWarning server\index.js`.

## B. Linux / macOS
```bash
node --version                      # must be v22.13+
unzip phoenix-x.zip && cd phoenix-x
./start.sh                          # creates .env + data/, starts on http://127.0.0.1:3000
```
Run as a service (Linux): copy to `/opt/phoenix-x`, create user `phoenix`, `chown -R phoenix /opt/phoenix-x/data`, install `deploy/phoenix-x.service`, `systemctl enable --now phoenix-x`.

## C. Docker
```bash
cp .env.example .env                # set PHOENIX_MODE=production for real use
docker compose up -d                # http://localhost:3000, data in the "phoenix-data" volume
# automatic HTTPS on your own domain (DNS must point at the server):
echo "PHOENIX_DOMAIN=soc.example.com" >> .env
docker compose --profile tls up -d
```
Logs: `docker compose logs -f phoenix`. Update: unzip the new version over the old, `docker compose up -d --build`.

## First production start: checklist
1. `PHOENIX_MODE=production` in `.env`.
2. *(Internet-facing)* set `PHOENIX_SETUP_TOKEN=<random string>` so nobody else can claim the first-admin screen.
3. Open the site → create the administrator (12+ characters, letters and digits). With `PHOENIX_REQUIRE_ADMIN_TOTP=on` you will be walked through authenticator enrolment.
4. **Settings → Asset inventory**: register your production hosts/users/buckets (anything unknown is treated fail-safe: approval needed).
5. **Connect a Platform**: pick Vercel / Render / Heroku / Netlify / Cloudflare / GitHub / VPS / AWS and follow the wizard ([PLATFORMS.md](PLATFORMS.md)). PHOENIX must be reachable from the internet over HTTPS for cloud platforms to send data: see [DEPLOY.md](DEPLOY.md).
6. *(Optional)* configure a containment connector (Okta / Entra / webhook) in `.env`. Leave `PHOENIX_CONNECTOR_DRYRUN=on` until you have watched a few dry-run incidents.
7. Enable backups: `PHOENIX_BACKUP_EVERY_HOURS=6`, and copy `data/backups/` off the machine.

## Verify the install
```bash
npm test                      # 6 suites (unit, persistence, API, connectors vs mocks, production e2e, platforms)
curl http://localhost:3000/healthz     # {"ok":true,...}
curl http://localhost:3000/readyz      # 200 when the DB works and the audit chain verifies
```

## Troubleshooting
| Symptom | Fix |
|---|---|
| `Cannot find module 'node:sqlite'` / `No such built-in module` | Node is too old. Install 22.13+. |
| Browser shows the login but "invalid credentials" | Production mode has no demo users. Use the account you created, or `npm run admin -- reset-password <user> <new-password>`. |
| Locked out after failed logins | Wait 15 min, or restart the server (lockouts are in memory). |
| "Invalid configuration" at start | Read the message: production refuses demo users, simulated connectors, or a TLS cert without a key. |
| Port already in use | Change `PORT` in `.env`. |
| Behind a proxy, every user looks like one IP | `PHOENIX_TRUST_PROXY=on`. |
| Reset everything (demo) | Stop, delete `data/phoenix.db*`, start. |
| Forgot admin password | `npm run admin -- reset-password admin "new-long-password-1"` (run on the server). |
