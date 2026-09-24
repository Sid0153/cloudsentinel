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
- `rules/` is pure Python as well (it reads its YAML metadata files, nothing else), and so is
  `risk/`: a score depends only on the rule, resource type, severity and evidence.

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
       6. evaluate(): every rule on every resource of its type → PASS / FAIL / UNKNOWN,
          plus a per-rule summary stored as scan.rule_results
       7. sync_findings(): create, update, reopen or close findings (see below); every
          detected finding is (re-)scored by the risk engine (docs/risk-model.md), and the
          scan stores a risk_summary
       8. COMPLETED, or COMPLETED_WITH_ERRORS when any service was not fully read or a rule
          crashed
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
| `app/domain/coverage.py` | Coverage statuses and which service produces each resource type |
| `app/rules/model.py` | Severity, rule metadata, `Outcome`, the `@check` decorator |
| `app/rules/checks/*.py` | The 8 checks, one file per area; pure functions |
| `app/rules/registry.py` | Explicit list of every check |
| `app/rules/catalog.py` | Loads `security-rules/rules/*.yaml` and pairs each file with its check |
| `app/rules/engine.py` | Runs the rules, builds detections and per-rule summaries |
| `app/findings/fingerprint.py` | Stable SHA-256 identity of "rule X failing on resource Y" |
| `app/findings/sync.py` | Applies one scan's results to the findings table |
| `app/findings/service.py` | Finding list filters and analyst status changes |
| `app/risk/model.py` | Risk factor levels, their points, priority bands |
| `app/risk/profiles.py` | Per-rule exposure / impact / confidence from the evidence |
| `app/risk/scoring.py` | `assess()` (score + breakdown) and the scan summary |

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

## Rule engine and findings (Phase 5)

Rules are described in `security-rules/README.md`. Each check returns one of:

| Outcome | Meaning | Effect on findings |
|---|---|---|
| PASS | evaluated and compliant (or not applicable) | may close an open finding |
| FAIL | non-compliant; carries evidence and a severity | creates or updates a finding |
| UNKNOWN | required data missing (access denied, service failed) | changes nothing |

Per rule, the scan stores a summary (`scan.rule_results`): `FAILED`, `PASSED` (everything
evaluated, coverage complete), `INCOMPLETE` (no finding, but something could not be evaluated or
a service was not fully read), `NOT_APPLICABLE` (no resources of that type, coverage complete) or
`ERROR` (the check raised an exception; details only in the server log).

### Finding lifecycle

One finding row per fingerprint = SHA-256 of `aws_account_id | rule_id | resource_type | region |
resource_id`. Evidence and severity are not part of it, so they can change while the finding
stays the same.

| Situation in a new scan | Result |
|---|---|
| New problem | new finding, `OPEN` |
| Detected again | `last_detected`, evidence and severity updated; `RESOLVED` → `OPEN` (reopened) |
| Detected again, analyst chose `ACKNOWLEDGED` or `FALSE_POSITIVE` | status kept |
| Rule evaluated the resource and it passed | `OPEN`/`ACKNOWLEDGED` → `RESOLVED` |
| Resource gone, its service fully read, region in scope | `OPEN`/`ACKNOWLEDGED` → `RESOLVED` |
| UNKNOWN outcome, service partly read, region not scanned | unchanged |

Automatic changes have `status_updated_by_id = NULL` and a short note; analyst changes
(`PATCH /api/findings/{id}`, ANALYST or ADMIN) record the user. `FALSE_POSITIVE` requires a note.
`scan.finding_counts` is a per-severity snapshot of what that scan detected.

### Known limitations of the rule engine

- The checks inherit every limitation of discovery listed above (for example IAM pattern
  matching). Each rule's YAML file lists what it does not check.
- Rule metadata is read once at startup; changing a YAML file needs a restart.
- Findings keep the title and severity of the latest detection. If a rule's text changes, open
  findings pick it up at the next scan; closed ones keep the old text.
- Risk scoring limitations are in `docs/risk-model.md`.

## Dashboard (Phase 7)

The React app (`frontend/src/`) only reads and writes through the REST API; it holds no data of
its own beyond the access token in memory.

| Page | Route | API |
|---|---|---|
| Dashboard | `/` | `GET /api/dashboard/summary` (optional `aws_account_id`) |
| Findings | `/findings` | `GET /api/findings` (filters, search, sort and page are kept in the URL) |
| Finding details | `/findings/:id` | `GET /api/findings/{id}`, `PATCH` for triage (ANALYST+) |
| Scans | `/scans` | `GET /api/scans`, `POST /api/scans` (ANALYST+); refreshes every 3 s while a scan runs |
| Scan details | `/scans/:id` | `GET /api/scans/{id}`, `GET /api/rules` |
| Resources | `/resources`, `/resources/:id` | `GET /api/resources`, findings filtered by `resource_uuid` |
| Settings | `/settings` | password change, AWS accounts (register and verify: ADMIN), rule catalog, health |
| Users | `/users` | ADMIN only |

- "Open" on the dashboard means OPEN or ACKNOWLEDGED. Overall risk is the highest risk score
  among open findings (and links to that finding); it is not an average or a sum.
- List endpoints return one page and put the total in the `X-Total-Count` header.
- Evidence and configuration are rendered as JSON text, never as HTML. Reference links are shown
  only for `https://` URLs and open with `rel="noopener noreferrer"`.
- Role checks in the UI only hide controls; the API enforces every permission.
- Charts are plain HTML bars (no chart library): one validated hue for single-series counts,
  every value printed as text, a hover title per bar.
- Code: `services/` (one file per API area), `hooks/useApi.ts` (loading / loaded / error state),
  `components/` (badges, bar list, cards, pagination), `pages/`.

Known limitations: no dark mode; no charts over time (scan-to-scan trends); the rule catalog is
read-only in the UI; admins cannot edit or delete AWS accounts from the UI yet.

## Audit log (Phase 8)

`audit_logs` is an append-only record of security-relevant actions, readable by ADMIN only
(`GET /api/audit-logs`, the Audit log page).

| Area | Events |
|---|---|
| Authentication | LOGIN_SUCCEEDED, LOGIN_FAILED (with reason), LOGIN_RATE_LIMITED, ACCOUNT_LOCKED, LOGOUT, PASSWORD_CHANGED (success or wrong current password), REFRESH_TOKEN_REUSED |
| Authorization | ACCESS_DENIED (a signed-in user called a route above their role) |
| Administration | USER_CREATED, USER_UPDATED (role / active flag, from and to), AWS_ACCOUNT_REGISTERED, AWS_ACCOUNT_VERIFIED |
| Scanning | SCAN_STARTED, SCAN_COMPLETED, SCAN_FAILED (including scans interrupted by a restart) |
| Findings | FINDING_STATUS_CHANGED (by an analyst: from, to, whether a note was given) |

Each record has the time, action, outcome (SUCCESS / FAILURE), actor (user ID and email at the
time; empty for anonymous or system events), target (type and ID), client IP, request ID (the
same ID as in the application log and the `X-Request-ID` header) and safe details.

- **Same transaction as the action.** `audit.record()` only adds the row; the caller's commit
  saves the change and its record together. Failure events (where nothing else changes) are
  committed right away.
- **Append-only in the database.** Triggers from migration 0006 reject UPDATE, DELETE and
  TRUNCATE on the table, whatever the code does. The actor foreign key has no ON DELETE action,
  so a user with audit history cannot be deleted (CloudSentinel only deactivates users).
- **No secrets.** Details are built from explicit fields per event; `sanitize()` then drops any
  key that looks like a password, token, secret or key, redacts secret-looking values and caps
  sizes. Failed logins never store the submitted email; finding notes stay on the finding.
- The request context (IP, request ID) comes from `RequestContextMiddleware` through context
  variables, so services do not need the HTTP request passed in.

Not recorded: successful token refreshes and unauthenticated 401s (too frequent to be useful),
reads (who viewed which finding), and status changes made by scans (automatic resolve and reopen:
the finding's `status_note` and the scan record show them). There is no retention policy or
export yet; the table grows until an operator archives it.

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
| Rule text in YAML, logic in Python | Text is reviewable without code; logic stays typed and unit-tested. A DSL would need its own parser and tests |
| No `rules` database table | Rules are versioned with the code; the API serves the catalog from memory. A table would duplicate it |
| Strict catalog loading at startup | A typo in a rule file stops the app instead of producing findings without remediation |
| Explicit check registry | `registry.py` is a plain list: easy to read, no import side effects |
| Account-wide rules run on the `AWS::Account` resource | "Is there any trail?" cannot be asked of a single trail |
| UNKNOWN never closes a finding | A denied API call must not make a problem disappear |
| Fingerprint from the 12-digit AWS account ID | Stable if the account is removed and registered again |
| Risk is a pure function of (rule, resource type, severity, evidence) | Deterministic and re-computable; the evidence documents the score |
| Additive points, not multiplication | Every point can be explained in one line; easy to test and to argue about |
| P1-P4 priorities instead of reusing LOW..CRITICAL | A HIGH-severity finding can be a P2; separate words avoid confusion |
| Risk data computed at scan time and stored | Sorting and filtering in SQL; the breakdown shows exactly what was used |
| One summary endpoint for the dashboard | One request, counts computed in SQL, consistent numbers across tiles |
| Totals in `X-Total-Count`, bodies stay plain lists | Pagination without changing the shape of existing list responses |
| Finding filters stored in the URL | Shareable, bookmarkable views; the back button works |
| No chart or state-management library | A few bar lists and fetch hooks do not justify the dependencies |
| Audit rows written in the same transaction as the action | An action is never saved without its record, or the reverse |
| Append-only enforced by database triggers, not only by the API | Holds against bugs and direct SQL as the application user |
| Real failure reason stored, generic message returned | Admins can tell brute force from a locked account; attackers learn nothing |
| Hash-pinned lockfiles from `uv pip compile --universal` | One lock valid on Windows, Linux and macOS; tampered packages are refused |
| Upgrade dependencies instead of silencing audits | React Router 7, Vite 8, Vitest 5 and pytest 9 fixed every reported advisory |
| Docs checked by tests (`openapi.json`, the role table in `api.md`) | Documentation cannot silently drift from the code |
| `check-config` before migrations | A misconfigured deployment fails with a readable message, not a stack trace |
