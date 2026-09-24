# CloudSentinel

An AWS cloud security monitoring and misconfiguration detection platform (portfolio project).

> **Status: Phase 9 of 10 (quality and DevOps).** CloudSentinel can register an AWS account, run a
> read-only scan, store the discovered resources, turn misconfigurations into findings with
> evidence and remediation, give each finding an explainable 0-100 risk score, show all of it in
> a web dashboard, and keep an append-only audit log of security-relevant actions for admins.
> This README will be rewritten in Phase 10 and will only
> describe what is actually implemented.

## What exists today

- FastAPI backend with `/api/health/live` and `/api/health/ready` (the latter checks PostgreSQL)
- Settings validated at startup (missing or short `SECRET_KEY` stops the app)
- Log redaction (passwords, tokens, AWS key IDs), request IDs, security headers, generic 500 errors
- SQLAlchemy + Alembic wired to PostgreSQL, with an empty baseline migration
- React + TypeScript + Vite + Tailwind frontend showing the live readiness result
- Docker Compose stack: PostgreSQL, backend, frontend (nginx)
- Authentication: Argon2id passwords, 15-minute access tokens, rotating httpOnly refresh cookie,
  account lockout and login rate limiting (details: `docs/security-model.md`)
- Roles ADMIN / ANALYST / VIEWER enforced on the server, with a test that every route has an
  access rule
- Frontend: login page, protected routes, admin-only Users page
- Audit log (Phase 8): logins, lockouts, access denied, user and AWS account changes, scans and
  finding triage, stored append-only (database triggers) and shown to admins on the Audit log page
- Dashboard (Phase 7): overall risk, open findings by severity and category, top risks, scan
  history with coverage and per-rule results, findings with filters, search, sorting and triage,
  finding details with evidence, risk explanation and remediation, resources, settings
- AWS discovery (API only, no UI yet): account identity, EC2 instances, security groups,
  S3 buckets (encryption, public access blocks, policy status, ACLs), IAM users and roles
  (MFA, console password, broad policy statements), CloudTrail trails
- Scans run in the background, record per-service coverage (`SUCCEEDED` / `PARTIAL` /
  `FAILED`), and never treat a denied API call as a clean result
- Least-privilege IAM policy: `infrastructure/cloudsentinel-readonly-policy.json`,
  explained in `docs/aws-permissions.md`
- Security rule engine (API only, no UI yet): 8 rules (SSH/RDP/broad inbound access, public
  and unencrypted S3 buckets, IAM users without MFA, broad IAM permissions, CloudTrail), listed
  in `security-rules/README.md`. Findings are de-duplicated across scans, closed automatically
  only when a scan proves the problem is gone, and can be triaged by analysts
  (`GET/PATCH /api/findings`, `GET /api/rules`)
- Risk engine: a deterministic 0-100 score per finding from severity, exposure, impact and
  confidence, with a stored point-by-point explanation and P1-P4 priorities
  (`docs/risk-model.md`)

## Run with Docker

```bash
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD and SECRET_KEY (commands are in the file)
docker compose up --build
```

- Frontend: http://localhost:8080
- API docs (backend directly): http://localhost:8000/api/docs
- Readiness: http://localhost:8000/api/health/ready

**Create the first administrator** (there is no public sign-up):

```bash
docker compose exec backend python -m app.cli create-admin --email you@example.com
```

It asks for a password (12 to 128 characters) without showing it. Then sign in at
http://localhost:8080.

**Scan a real AWS account (optional).** The default stack has no AWS access. Follow
`docs/aws-permissions.md` to create a read-only identity and profile, then:

```bash
docker compose -f docker-compose.yml -f docker-compose.aws.yml up --build
```

Using the API docs at http://localhost:8000/api/docs, register the account
(`POST /api/aws-accounts`), verify it (`POST /api/aws-accounts/{id}/verify`), start a scan
(`POST /api/scans`) and read the results (`GET /api/scans/{id}`, `GET /api/resources`,
`GET /api/findings`).

To wipe the database (for example after changing `POSTGRES_PASSWORD`): `docker compose down -v`.

## Run tests

Backend (from `backend/`):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt   # the lockfile: exact, hash-checked
pytest   # database-backed tests are skipped unless TEST_DATABASE_URL is set
# AWS is mocked with moto and the tests use fake credentials: no AWS account is needed
# full suite against a scratch PostgreSQL database (tables are created and dropped):
TEST_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@localhost:5432/scratch_db pytest --cov=app
ruff check . && mypy
pip-audit -r requirements.txt --require-hashes --disable-pip   # known vulnerabilities
```

Dependencies: edit the ranges in `requirements.in` / `requirements-dev.in`, then regenerate the
lockfiles with the `uv pip compile` command written at the top of each `.txt` file.

Frontend (from `frontend/`):

```bash
npm ci          # installs exactly what package-lock.json records
npm run lint    # ESLint
npm run typecheck
npm test
npm run build
npm audit --audit-level=moderate
```

CI (`.github/workflows/ci.yml`) runs all of the above, a secret scan of the whole git history
(gitleaks) and a Docker Compose smoke test that also checks the containers run hardened.
Dependabot opens weekly update pull requests. API reference: `docs/api.md` and
`docs/openapi.json`.

## Local development without Docker

Start only the database (`docker compose up db`), then in `backend/` set `DATABASE_URL` and
`SECRET_KEY` in your environment (or a `backend/.env`), run
`alembic upgrade head`, then `uvicorn app.main:create_app --factory --reload`.
In `frontend/`, `npm run dev` serves on http://localhost:5173 and proxies `/api` to port 8000.

## Repository layout

```
backend/         FastAPI app (app/), Alembic migrations (alembic/), tests (tests/)
  app/aws/       boto3 session, collectors (AWS calls) and normalizers (pure functions)
  app/scans/     scan orchestration and persistence
  app/rules/     rule engine and checks (pure Python, no AWS or database code)
  app/findings/  fingerprints, finding sync after each scan, triage
  app/risk/      risk scoring (pure Python)
  app/domain/    typed resource models shared by everything else
frontend/        React + TypeScript + Vite + Tailwind (src/), tests (tests/)
security-rules/  rule metadata (one YAML file per rule) and the rule list
docs/            architecture, security model, risk model, API (api.md, openapi.json), AWS permissions
infrastructure/  least-privilege IAM policy
docker-compose.yml, docker-compose.aws.yml (optional AWS access), .env.example
```
