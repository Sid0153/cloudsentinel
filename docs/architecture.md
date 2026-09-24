# Architecture

CloudSentinel is a modular monolith: one FastAPI service, one React single-page app, one
PostgreSQL database.

```
Browser ──► nginx (frontend container) ──/api──► FastAPI ──► PostgreSQL
                                                    │
                                                    └──► AWS APIs (read-only, boto3)
```

## Dependency direction

```
api  →  services / scans  →  aws / rules / risk / audit  →  domain
                  ↓
             models + database
```

- `aws/` is the only package that imports boto3.
- `domain/` holds plain dataclasses with no boto3, database or HTTP code.
- `rules/` and `risk/` (Phases 5-6) will be pure Python as well.

## Scan pipeline (Phase 4)

```
POST /api/scans (ANALYST+)
  └─ create_scan: lock the account row, refuse if a scan is already PENDING/RUNNING, insert PENDING
  └─ 202 Accepted, then a background task runs execute_scan:
       1. RUNNING
       2. build a boto3 session (credential chain, optional AssumeRole)
       3. sts:GetCallerIdentity → must match the registered account ID, else FAILED
       4. discover(): for each service
            collector (boto3 calls, per-region, errors recorded)  → raw data
            normalizer (pure function)                             → NormalizedResource list
            coverage entry: SUCCEEDED / PARTIAL / FAILED, item count, short error labels
          A crash in one service marks only that service FAILED.
       5. upsert_resources(): one row per resource, updated in place (first_seen / last_seen)
       6. COMPLETED, or COMPLETED_WITH_ERRORS when any service was not fully read
GET /api/scans/{id} — poll for status, counts and coverage
```

| Module | Responsibility |
|---|---|
| `app/aws/session.py` | boto3 session and STS identity |
| `app/aws/collectors/*.py` | One file per service; only AWS calls and error capture |
| `app/aws/normalizers/*.py` | Raw AWS dicts → typed `NormalizedResource` objects |
| `app/scans/discovery.py` | Runs collectors and normalizers, builds coverage |
| `app/scans/persistence.py` | Upserts resources |
| `app/scans/service.py` | Scan lifecycle: create, execute, reconcile after restart |
| `app/scans/deps.py` | Injection points so tests can run scans inline or simulate failures |

### Supported resources

| Type | Collected via | Notes |
|---|---|---|
| `AWS::Account` | STS | One per scan target |
| `AWS::EC2::Instance` | DescribeInstances | Terminated instances skipped |
| `AWS::EC2::SecurityGroup` | DescribeSecurityGroups | Attachments from EC2 instances only |
| `AWS::S3::Bucket` | S3 + S3 Control | Region, encryption, public access blocks, policy status, ACL |
| `AWS::IAM::User` | Credential report + GetAccountAuthorizationDetails | MFA, password, keys, broad statements |
| `AWS::IAM::Role` | GetAccountAuthorizationDetails | Attached policies, broad statements |
| `AWS::CloudTrail::Trail` | DescribeTrails + GetTrailStatus | Multi-region, logging, validation |

### Known limitations of discovery

- Security group attachments consider EC2 instances only (not load balancers, RDS, Lambda).
- IAM analysis is pattern matching: an Allow with `*` or `service:*` on Resource `*`. NotAction,
  NotResource, permission boundaries, SCPs and resource policies are not analyzed. AWS-managed
  policies are recognized only as `AdministratorAccess`.
- CloudTrail: event selectors, delivery health and organization-level coverage are not checked.
- S3 bucket region is "unknown" if `GetBucketLocation` fails.
- Only the regions registered for the account are scanned. Only the `aws` partition is supported.
- Resources deleted in AWS stay in the table; `last_seen` shows when they were last found.
- Background tasks run inside the API process, so this design assumes a single backend
  instance. A job queue (for example Celery or RQ) would be the next step.

## Decisions

| Decision | Why |
|---|---|
| Modular monolith | One deployable unit is enough; separation comes from packages |
| Synchronous SQLAlchemy and route handlers | boto3 is synchronous; simpler to read and debug |
| Settings via environment, no secret defaults | A misconfigured deployment fails at startup |
| Application factory (`create_app`) | Tests can build an app with custom settings |
| Alembic from the first phase | Schema changes are versioned from day one |
| API served under `/api`, same origin via nginx | No CORS in the Docker setup; simpler cookies |
| Collect → normalize split | Normalizers are pure and tested with fixtures; collectors with moto |
| "Unknown" is a first-class value | A denied API call must never look like a secure setting |
| One resource row per resource, snapshot counts per scan | Stable IDs for findings later; history stays accurate |
| FastAPI BackgroundTasks, not Celery | No extra infrastructure; the scan code does not depend on it |
