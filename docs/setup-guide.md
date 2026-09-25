# Setup guide

From a fresh clone to a first scan. Commands work in Git Bash, macOS and Linux shells;
PowerShell equivalents are given where they differ.

## 1. Requirements

- Docker Desktop (or Docker Engine with the Compose plugin v2.17+; the backend build uses an
  extra build context).
- Optional, for development without Docker: Python 3.12, Node 22+.
- Optional, for real scans: an AWS account you are allowed to inspect, and the AWS CLI.

## 2. Configure

```bash
cp .env.example .env
```

Fill in the two blanks in `.env`:

| Variable | How to generate |
|---|---|
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` |
| `SECRET_KEY` | `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |

`.env` is git-ignored; never commit it. The backend refuses to start with a missing or weak
`SECRET_KEY` and prints which setting is wrong (never its value).

## 3. Start

```bash
docker compose up --build
```

The backend waits for PostgreSQL, checks its configuration (`check-config`), applies the
database migrations and starts. When all three containers are healthy:

- App: http://localhost:8080
- API docs: http://localhost:8000/api/docs (disabled when `APP_ENV=production`)
- Readiness: http://localhost:8080/api/health/ready should return `{"status":"ok","database":"up"}`

## 4. Create the first administrator

There is no public sign-up. On the server:

```bash
docker compose exec backend python -m app.cli create-admin --email you@example.com
```

It prompts for a password (12 to 128 characters) without echoing it. Sign in at
http://localhost:8080 and create other users on the **Users** page (roles: VIEWER, ANALYST,
ADMIN).

## Try it without AWS: sandbox mode

To see everything working without an AWS account, start the stack with the sandbox override
instead of steps 4 to 6:

```bash
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up --build
```

Open http://localhost:8080, click **Explore as guest**, start a scan, then break or fix settings
on the **Sandbox** page and scan again. Scans run against a simulated AWS account
([sandbox.md](sandbox.md)); nothing touches a real one.

## 5. Give CloudSentinel read-only AWS access (for real scans)

Follow [aws-permissions.md](aws-permissions.md): create an identity with the 14-action
read-only policy in `infrastructure/cloudsentinel-readonly-policy.json` and a named AWS CLI
profile (SSO recommended). Never put access keys in `.env`, the code or the UI.

Then add to `.env`:

```bash
AWS_PROFILE=cloudsentinel
AWS_CONFIG_DIR=/home/you/.aws        # Windows: C:/Users/you/.aws
```

and start the stack with the AWS override, which mounts that folder read-only:

```bash
docker compose -f docker-compose.yml -f docker-compose.aws.yml up --build
```

For an SSO profile, run `aws sso login --profile cloudsentinel` on your machine first.

## 6. First scan

1. **Settings → AWS accounts** (ADMIN): register the 12-digit account ID, a name, the regions
   to scan and, optionally, a role ARN to assume.
2. Click **Verify access**: it should say the credentials resolve to the same account.
3. **Scans → Start scan** (ANALYST or ADMIN). The page refreshes while it runs.
4. Open the scan to see per-service coverage and per-rule results, then the **Dashboard** and
   **Findings**.

A scan that could not read something ends as *Completed with errors* and marks the affected
rules *Incomplete*: that means "could not check", not "secure".

## 7. Development without Docker

```bash
docker compose up -d db                       # only PostgreSQL
cd backend
python3 -m venv .venv && source .venv/bin/activate    # PowerShell: .venv\Scripts\activate
pip install --require-hashes -r requirements-dev.txt
export DATABASE_URL=postgresql+psycopg://USER:PASSWORD@127.0.0.1:5432/cloudsentinel
export SECRET_KEY=...                          # or put both in backend/.env
alembic upgrade head
uvicorn app.main:create_app --factory --reload
```

```bash
cd frontend
npm ci
npm run dev        # http://localhost:5173, proxies /api to port 8000
```

Tests and checks: see "Running tests" in the [README](../README.md).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `set POSTGRES_PASSWORD in .env` from compose | `.env` missing or a value empty; see step 2 |
| Backend exits with `Configuration errors:` | The listed setting is invalid (e.g. short `SECRET_KEY`, or http CORS origins with `APP_ENV=production`) |
| `Cannot connect to the database` | PostgreSQL not ready, or `DATABASE_URL` wrong (outside Docker, use `127.0.0.1`) |
| Password authentication failed after changing `POSTGRES_PASSWORD` | The database volume keeps the old password: `docker compose down -v` (deletes the data) |
| Sign-in keeps saying "Incorrect email or password" | After 5 failures the account is locked for 15 minutes; the reason is in the audit log |
| Scan `FAILED`: "Could not authenticate to AWS" | No AWS profile available to the backend; see step 5 |
| Scan `FAILED`: "credentials belong to account X" | The profile points at a different account than the one registered |
| Scan *Completed with errors* | A permission is missing; the scan's coverage table names the API call |
| `docker run -v` paths broken in Git Bash | Prefix the command with `MSYS_NO_PATHCONV=1` |
