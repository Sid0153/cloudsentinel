# CloudSentinel

[![CI](https://github.com/Sid0153/cloudsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Sid0153/cloudsentinel/actions/workflows/ci.yml)

A read-only AWS security scanner with a web dashboard. CloudSentinel connects to an AWS account
through boto3, discovers EC2, S3, IAM and CloudTrail resources, checks them against eight
security rules, gives every finding an explainable 0-100 risk score, and lets a team triage the
results, with role-based access and an append-only audit log.

It is a portfolio project (final-year B.Tech IT). Everything below describes what is
implemented and tested; limitations are listed at the end.

## 1. Project overview

| | |
|---|---|
| Backend | FastAPI (Python 3.12), SQLAlchemy 2, Alembic, PostgreSQL 16, boto3 |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, React Router 7 |
| Runs as | Docker Compose: nginx (serves the app, proxies `/api`), backend, database |
| Tests | 425 backend (pytest, moto, real PostgreSQL; 96% coverage), 61 frontend (Vitest, Testing Library) |
| CI | GitHub Actions: lint, types, tests, dependency audits, secret scan, Docker smoke test |

## 2. Problem statement

Most cloud breaches start with misconfiguration, not exotic exploits: SSH open to the internet,
a public bucket, an admin user without MFA, logging switched off. AWS offers the raw
information through its APIs, but a small team needs it collected, checked, prioritized and
tracked over time, without handing a tool broad write access to the account and without a
missing permission quietly turning into "no problems found".

## 3. Features

- **Read-only AWS discovery:** account identity (STS), EC2 instances, security groups, S3
  buckets (encryption, Block Public Access at bucket and account level, policy status, ACL),
  IAM users and roles (console password, MFA, access keys, wildcard permissions), CloudTrail
  trails. A scan refuses to run if the credentials belong to a different account.
- **Honest coverage:** each service is recorded as `SUCCEEDED`, `PARTIAL` or `FAILED`; a denied
  API call becomes *could not check*, never *secure*.
- **Eight security rules** (`security-rules/`): SSH and RDP open to the internet, broad inbound
  access (severity by port), public S3 bucket (CRITICAL if publicly writable), S3 without
  default encryption, console user without MFA, overly broad IAM permissions, no multi-region
  CloudTrail trail logging. Each has evidence, remediation steps, references and documented
  limitations.
- **Findings lifecycle:** de-duplicated across scans by fingerprint; closed automatically only
  when a scan proves the problem is gone; reopened if it comes back; triage by analysts
  (acknowledge, resolve, false positive with a required note).
- **Explainable risk score:** severity + exposure + impact + confidence adjustment, 0-100, P1-P4
  priorities, with the reason for every point stored on the finding (`docs/risk-model.md`).
- **Dashboard:** overall risk, open findings by severity and category, top risks, scan history
  with per-service coverage and per-rule results, findings with search, filters, sorting and
  paging, resources, settings, user administration.
- **Security:** Argon2id passwords, short-lived access tokens, rotating refresh cookie with reuse
  detection, lockout and rate limiting, role-based access enforced on every route (tested for
  every route and role), append-only audit log enforced by database triggers.

## 4. Architecture

```
Browser ──► nginx (React app, security headers) ──/api──► FastAPI ──► PostgreSQL
                                                             │
                                                             └──► AWS APIs (boto3, read-only)

Scan pipeline (background task):
  STS identity check ─► collectors (boto3) ─► normalizers (pure) ─► rule engine (pure)
      ─► risk engine (pure) ─► findings sync ─► scan summary + audit record
```

`aws/` is the only package that imports boto3; `domain/`, `rules/` and `risk/` are plain Python
with no AWS, database or HTTP code, which keeps them easy to test. Details and design decisions:
[docs/architecture.md](docs/architecture.md).

## 5. Technology stack

- **Python 3.12, FastAPI, Pydantic 2**: typed request validation and OpenAPI docs.
- **SQLAlchemy 2 + Alembic + PostgreSQL 16**: relational data, JSONB for per-type configuration
  and evidence, versioned migrations.
- **boto3**: AWS APIs through the standard credential chain.
- **React 18 + TypeScript + Vite + Tailwind**: single-page app; no chart or state library.
- **pytest, moto, Vitest, Testing Library**; **ruff, mypy --strict, ESLint**; **uv** (lockfiles),
  **pip-audit, npm audit, gitleaks**; **Docker Compose**, **GitHub Actions**, **Dependabot**.

## 6. Repository structure

```
backend/
  app/api/          REST routes (thin: validation, auth, call a service)
  app/auth/         passwords, tokens, sessions, role dependencies
  app/aws/          boto3 session, collectors (AWS calls), normalizers (pure)
  app/scans/        scan lifecycle, discovery, persistence
  app/rules/        rule engine, catalog loader, checks (pure)
  app/risk/         risk model and per-rule profiles (pure)
  app/findings/     fingerprints, findings sync, queries and triage
  app/audit/        audit events and recording
  app/domain/       typed resource models shared by everything
  app/models/       SQLAlchemy tables      app/schemas/  API models
  alembic/          migrations 0001-0006   tests/        unit, API, integration
frontend/src/       pages, components, services (API calls), hooks, types
security-rules/     one YAML file per rule (text, severity, remediation, references)
infrastructure/     least-privilege IAM policy for the scanner
docs/               architecture, security model, threat model, risk model, API, database,
                    AWS permissions, setup guide, demo checklist
```

## 7. Setup instructions

```bash
cp .env.example .env          # set POSTGRES_PASSWORD and SECRET_KEY (commands in the file)
docker compose up --build
docker compose exec backend python -m app.cli create-admin --email you@example.com
```

Open http://localhost:8080 and sign in. The full walkthrough, including troubleshooting, is in
[docs/setup-guide.md](docs/setup-guide.md).

## 8. AWS setup

Create a dedicated identity (SSO permission set, a role to assume, or a lab-only IAM user) with
the read-only policy below, configure it as a named AWS CLI profile, and start the stack with
the AWS override, which mounts your AWS config folder read-only:

```bash
# in .env: AWS_PROFILE=cloudsentinel and AWS_CONFIG_DIR=/path/to/.aws
docker compose -f docker-compose.yml -f docker-compose.aws.yml up --build
```

Then, in the app: **Settings → AWS accounts** (register, *Verify access*) and **Scans → Start
scan**. No credential is ever entered in the UI, stored in the database or committed.
Step by step: [docs/aws-permissions.md](docs/aws-permissions.md).

## 9. Required IAM permissions

Fourteen read-only actions ([policy file](infrastructure/cloudsentinel-readonly-policy.json)):
`ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `s3:ListAllMyBuckets`,
`s3:GetBucketLocation`, `s3:GetEncryptionConfiguration`, `s3:GetBucketPublicAccessBlock`,
`s3:GetAccountPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`,
`iam:GenerateCredentialReport`, `iam:GetCredentialReport`,
`iam:GetAccountAuthorizationDetails`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`.

It cannot read S3 object contents or change anything. `AdministratorAccess`, `ReadOnlyAccess`
and the root user are not needed and not recommended. A test reads the collectors' code and
fails if the policy grants anything the code does not call, or misses anything it does.

## 10. Environment variables

| Variable | Required | Meaning |
|---|---|---|
| `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_PASSWORD` | yes (Docker) | Database; the backend's `DATABASE_URL` is built from them in compose |
| `SECRET_KEY` | yes | Signs access tokens; 32+ random characters (validated) |
| `APP_ENV` | no | `development` (default), `test`, `production` (stricter checks, API docs off, `Secure` cookie) |
| `LOG_LEVEL` | no | `INFO` by default; `DEBUG` is refused in production |
| `CORS_ORIGINS` | no | Comma-separated origins; no wildcards; must be `https://` in production |
| `DATABASE_URL` | outside Docker | `postgresql+psycopg://user:password@127.0.0.1:5432/db` |
| `AWS_PROFILE`, `AWS_CONFIG_DIR` | for real scans | Used by `docker-compose.aws.yml`; no keys in `.env` |

`python -m app.cli check-config` validates all of it (the container runs it at start-up) and
names bad settings without printing their values.

## 11. Running locally

With Docker, see sections 7 and 8. Without Docker (hot reload):

```bash
docker compose up -d db
cd backend && pip install --require-hashes -r requirements-dev.txt
export DATABASE_URL=... SECRET_KEY=...
alembic upgrade head && uvicorn app.main:create_app --factory --reload
cd ../frontend && npm ci && npm run dev    # http://localhost:5173, proxies /api
```

## 12. Running tests

Backend (from `backend/`), against a scratch PostgreSQL database:

```bash
export TEST_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@127.0.0.1:5432/cloudsentinel_test
pytest --cov=app          # 425 tests; AWS is mocked with moto, credentials are fake
ruff check . && mypy
pip-audit -r requirements.txt --require-hashes --disable-pip
```

Frontend (from `frontend/`):

```bash
npm ci && npm run lint && npm run typecheck && npm test && npm run build
npm audit --audit-level=moderate
```

No test needs a real AWS account. CI runs all of this plus a gitleaks scan of the whole git
history and a Docker Compose smoke test that also checks the containers run as non-root, with
no Linux capabilities and a read-only filesystem.

## 13. Example scan

The output below comes from the automated test environment: the real scan pipeline running
against **moto** (a local AWS simulator) seeded with a deliberately mixed setup
(`backend/tests/aws/seed.py`). It is not a real AWS account.

```json
{
  "status": "COMPLETED",
  "resource_count": 12,
  "coverage": {"ec2": "SUCCEEDED", "s3": "SUCCEEDED", "iam": "SUCCEEDED", "cloudtrail": "SUCCEEDED"},
  "finding_counts": {"HIGH": 5, "MEDIUM": 2},
  "risk_summary": {"max_score": 85, "by_priority": {"P1": 4, "P2": 1, "P3": 0, "P4": 2}},
  "rule_results": {
    "CS-CT-001": "PASSED", "CS-IAM-001": "FAILED", "CS-IAM-002": "FAILED", "CS-S3-001": "FAILED",
    "CS-S3-002": "FAILED", "CS-SG-001": "FAILED", "CS-SG-002": "PASSED", "CS-SG-003": "PASSED"
  }
}
```

## 14. Example findings

From the same test scan, highest risk first:

| Risk | Severity | Finding | Resource |
|---|---|---|---|
| 85 · P1 | HIGH | S3 bucket is publicly accessible | `cs-public-bucket` |
| 85 · P1 | HIGH | IAM user with a console password has no MFA | user `alice` (has `*` permissions) |
| 85 · P1 | HIGH | Security group allows SSH from the internet | group attached to a running public instance |
| 80 · P1 | HIGH | IAM identity has overly broad permissions | user `alice` |
| 75 · P2 | HIGH | IAM identity has overly broad permissions | role `ops-admin` |
| 35 · P4 | MEDIUM | S3 bucket has no default encryption configured | two buckets (moto does not apply AWS's default encryption) |

One finding in full (IDs shortened):

```json
{
  "rule_id": "CS-SG-001",
  "severity": "HIGH",
  "risk_score": 85,
  "evidence": {
    "port": 22,
    "open_rules": [{"protocol": "tcp", "ports": "22", "sources": ["0.0.0.0/0"]}],
    "attached_instance_ids": ["i-e91e…"],
    "internet_facing_instance_ids": ["i-e91e…"],
    "attachments_known": true
  },
  "risk_breakdown": {
    "severity":   {"level": "HIGH", "points": 40},
    "exposure":   {"level": "INTERNET", "points": 25, "reason": "Attached to 1 running instance(s) with a public IP address"},
    "impact":     {"level": "HIGH", "points": 20, "reason": "Remote administration: a guessed or leaked credential gives a shell"},
    "confidence": {"level": "HIGH", "points": 0, "reason": "All inputs were available"},
    "score": 85, "priority": "P1"
  }
}
```

## 15. Security considerations

- **Read-only by design:** the code only calls read APIs (plus `GenerateCredentialReport`, which
  changes nothing) and never remediates automatically.
- **No stored credentials:** boto3's credential chain; optional `AssumeRole`; the scan verifies
  the account ID first.
- **Authentication and authorization:** see [docs/security-model.md](docs/security-model.md);
  every route has a declared role, tested for every role.
- **Audit:** logins, lockouts, access denied, admin changes, scans and triage are recorded in an
  append-only table; secrets are never stored in it.
- **Secrets hygiene:** log redaction, validation errors without values, no secrets in the repo
  (gitleaks in CI).
- **Supply chain and runtime:** hash-pinned lockfiles, dependency audits, Dependabot, non-root
  read-only containers without capabilities, CSP and other security headers.
- Threats, mitigations and residual risks: [docs/threat-model.md](docs/threat-model.md).

## 16. Limitations

- **Never run against a real AWS account by the author yet;** all automated scanning uses moto,
  which does not implement everything (for example bucket policy status is supplied by the tests).
- **Coverage:** four services (EC2, S3, IAM, CloudTrail) and only the registered regions and the
  `aws` partition. No RDS, Lambda, EKS, KMS, VPC flow logs, GuardDuty, etc.
- **Check depth:** IAM is pattern matching (`*` or `service:*` on `*`; AdministratorAccess by
  name), not a policy simulator. Security-group exposure considers EC2 instances only. CloudTrail
  checks existence, multi-region scope and logging status only. Each rule's YAML lists its limits.
- **Risk model:** CloudSentinel's own documented model, not CVSS; weights are judgement, not
  calibrated on incident data; no data-sensitivity or business context.
- **Single instance:** scans run as in-process background tasks; rate-limit and lockout
  counters are per process; a restart fails running scans (they are marked FAILED).
- **Accounts:** no MFA, password reset or SSO for CloudSentinel users; AWS accounts cannot be
  edited or deleted from the UI.
- **Operations:** no TLS in the compose stack (put a TLS-terminating proxy in front), no audit
  log retention/export, no trend charts, no dark mode.

## 17. Future improvements

- More services and rules (RDS public snapshots, EBS encryption, KMS rotation, Lambda URLs,
  GuardDuty/Security Hub status); multi-account via AWS Organizations.
- A job queue (e.g. RQ/Celery) for scans, scheduled scans, and horizontal scaling with a shared
  rate-limit store.
- IAM analysis with the IAM policy simulator or Access Analyzer instead of pattern matching.
- MFA and SSO (OIDC) for CloudSentinel users; audit log export to a SIEM with tamper-evident
  hashing.
- Trends over time, notifications (email/Slack) for new P1 findings, and exports (CSV, SARIF).
- Supply chain: pin actions and base images by digest, container image scanning, SBOM.

## Documentation

[Architecture](docs/architecture.md) · [Security model](docs/security-model.md) ·
[Threat model](docs/threat-model.md) · [Risk model](docs/risk-model.md) · [API](docs/api.md) ·
[Database](docs/database-schema.md) · [AWS permissions](docs/aws-permissions.md) ·
[Setup guide](docs/setup-guide.md) · [Demo and screenshots](docs/demo.md) ·
[Security rules](security-rules/README.md)
