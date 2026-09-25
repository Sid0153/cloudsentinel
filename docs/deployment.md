# Free public deployment

A public link where anyone can use the real app, at no cost and without an AWS account: the
backend runs in [sandbox mode](sandbox.md) (it scans a simulated AWS account) and visitors
click **Explore as guest**. It is a demo for a portfolio, not a service for customers.

## What runs where

| Part | Where | Free plan terms (checked September 2026) |
|---|---|---|
| React app | Render static site `cloudsentinel-demo` | Always on; proxies `/api/*` to the backend |
| Backend + simulator | Render free web service `cloudsentinel-demo-api` (`deploy/Dockerfile`) | Stops after 15 minutes without traffic; 750 free instance hours a month per workspace; 512 MB RAM |
| PostgreSQL | Neon free project | 0.5 GB storage, 100 compute-hours a month, suspends after 5 minutes idle |

Everything is described in [`render.yaml`](../render.yaml) (a Render Blueprint). Render's own
free PostgreSQL is not used because it is deleted 30 days after creation.

**One container, two processes.** Render's free plan has no private services, and the
simulator accepts any credentials, so it must not get a public address. `deploy/Dockerfile`
therefore runs it inside the backend container on `127.0.0.1:5000`, restarted automatically
if it stops (`deploy/start.sh`). CI checks that only the app's port listens on all interfaces.

**Same origin.** The static site rewrites `/api/*` to the backend, so the browser talks to one
address: the refresh cookie (`SameSite=Strict`, `Secure`) and the CSP work as in Docker
Compose.

**Measured under the free plan's limits** (512 MB, 0.1 CPU; CI repeats this on every push):
start-up about 2 minutes (the first request after a stop also waits for Render to start the
container); memory steady at about 340 MB after scans and sandbox changes; first sandbox page
load about 17 s (it builds the simulated account), later changes 2 to 5 s; a scan 3 to 10 s.

## Steps

Nobody else can do these for you: they create accounts and connect your GitHub repository.
Never paste the database URL into chat, issues or the repository.

1. **Neon**: sign up at https://neon.com (GitHub sign-in works). Create a project named
   `cloudsentinel`, region **AWS Asia Pacific (Singapore)** (the same region as the Render
   services in `render.yaml`; change both if you prefer another). On the dashboard, open
   **Connect**, turn **connection pooling off**, and copy the connection string. Change its
   start from `postgresql://` to `postgresql+psycopg://` (the backend refuses other drivers).
2. **Render**: sign up at https://render.com with GitHub. Choose **New → Blueprint**, allow
   Render to read the `cloudsentinel` repository, and select it. Render reads `render.yaml` and
   asks for `DATABASE_URL`: paste the edited Neon string. Apply.
3. Wait for both services to deploy (the first build takes several minutes). If Render says a
   service name is taken, choose another name and update the `/api/*` rewrite and
   `CORS_ORIGINS` in `render.yaml` to the backend's real address.
4. Open https://cloudsentinel-demo.onrender.com and click **Explore as guest**.

At start-up the backend applies the migrations, registers the simulated AWS account and
creates the guest account (`deploy/start.sh` → `backend/docker-entrypoint.sh`).

**Admin account (optional).** Free web services have no shell. To create an admin, run the CLI
on your own machine against the Neon database, in your own terminal:

```bash
cd backend
export DATABASE_URL='postgresql+psycopg://...neon.tech/neondb?sslmode=require'
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m app.cli create-admin --email you@example.com
```

(A throwaway `SECRET_KEY` is enough here: settings need one, and the server keeps its own.)

## Updates

`autoDeployTrigger: checksPass`: Render deploys a commit to `main` only after its GitHub
checks (CI) have passed. Pull-request previews are off so Dependabot does not use free hours.

## Limits to be honest about

- **Cold starts.** After 15 minutes without visitors the backend stops; the next visitor waits
  two or three minutes. The app shows a notice meanwhile. Neon adds under a second when it
  was suspended.
- **Simulated AWS.** Say so wherever you show it (the app does, on every page).
- **Shared data.** All visitors use the same guest account and the same simulated account;
  one visitor's changes are visible to the others. **Reset to defaults** restores the sandbox.
- **Single instance.** Rate limits and the simulator's state are in memory and reset when the
  container restarts; the backend rebuilds the simulated account when it finds it empty.
- **Free plans change.** Re-check Render's and Neon's terms if something stops working.
