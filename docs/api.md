# API

Base path `/api`. The complete machine-readable description is [`openapi.json`](openapi.json)
(regenerate it with `python -m app.cli export-openapi` from `backend/`; a test fails when it is
out of date). While the app runs outside production, interactive docs are at `/api/docs`.

## Conventions

- **Authentication.** `POST /api/auth/login` returns an access token (15 minutes) and sets a
  refresh cookie (`httpOnly`, `SameSite=Strict`, path `/api/auth`). Send the token as
  `Authorization: Bearer <token>`. Details: [security-model.md](security-model.md).
- **Roles.** VIEWER reads, ANALYST also starts scans and triages findings, ADMIN also manages
  users and AWS accounts and reads the audit log. The server enforces this on every route; the
  table below is checked against the authorization tests.
- **Lists** return one page (`limit`, `offset`) as a JSON array; the `X-Total-Count` response
  header holds the total number of matches.
- **Errors** are JSON with a `detail` field: 401 not signed in, 403 role too low, 404 not found,
  409 conflict, 422 invalid input (never echoing the submitted values), 429 too many requests
  (sign-ins, scans started, sandbox changes; per client IP), 502 AWS unreachable, 503 simulated
  AWS unreachable (sandbox mode). Unexpected errors return 500 with a `request_id` to find the
  server log entry.
- **Sandbox mode and guest access** are off unless configured
  ([sandbox.md](sandbox.md)). While off, `/api/sandbox*` and `/api/auth/guest` answer 404.
- Every response carries `X-Request-ID`, the same ID as in the server log and the audit log.

## Endpoints

| Endpoint | Role | Purpose |
|---|---|---|
| `GET /api/health/live` | public | The process is up |
| `GET /api/health/ready` | public | The database is reachable (503 if not) |
| `POST /api/auth/login` | public | Sign in; rate limited per IP, account lockout after repeated failures |
| `POST /api/auth/refresh` | public (cookie) | New access token; rotates the refresh token |
| `POST /api/auth/logout` | public (cookie) | End the session |
| `POST /api/auth/guest` | public | Sign in as the shared guest account (only with `GUEST_EMAIL`); rate limited per IP |
| `GET /api/about` | public | Version, whether sandbox mode and guest access are on |
| `GET /api/auth/me` | any signed-in user | The current user |
| `POST /api/auth/change-password` | any signed-in user | Change your password; signs out every session (not for the guest account) |
| `GET /api/users` | ADMIN | List users |
| `POST /api/users` | ADMIN | Create a user |
| `PATCH /api/users/{user_id}` | ADMIN | Change role or active flag (not your own) |
| `GET /api/aws-accounts` | any signed-in user | Registered AWS accounts |
| `POST /api/aws-accounts` | ADMIN | Register an account (ID, name, regions, optional role ARN; no credentials) |
| `POST /api/aws-accounts/{aws_account_id}/verify` | ADMIN | Check which AWS identity the backend's credentials resolve to |
| `GET /api/scans` | any signed-in user | Scan history, newest first |
| `POST /api/scans` | ANALYST | Queue a read-only scan (202); one active scan per account; rate limited per IP |
| `GET /api/scans/{scan_id}` | any signed-in user | Scan status, coverage, per-rule results, counts, risk summary |
| `GET /api/resources` | any signed-in user | Discovered resources (filter by account, type, region) |
| `GET /api/resources/{resource_uuid}` | any signed-in user | One resource with its configuration |
| `GET /api/findings` | any signed-in user | Findings: filters, search, sort (risk by default) |
| `GET /api/findings/{finding_id}` | any signed-in user | Evidence, risk breakdown, rule text and remediation |
| `PATCH /api/findings/{finding_id}` | ANALYST | Triage: status and note (FALSE_POSITIVE needs a note) |
| `GET /api/rules` | any signed-in user | The security rule catalog |
| `GET /api/dashboard/summary` | any signed-in user | Overall risk, counts, latest scan, top risks |
| `GET /api/audit-logs` | ADMIN | Audit events, newest first, with filters |
| `GET /api/sandbox` | any signed-in user | Sandbox mode: the simulated account and every switch's state |
| `PATCH /api/sandbox/controls/{key}` | ANALYST | Sandbox mode: make one setting insecure or fix it; rate limited per IP |
| `POST /api/sandbox/reset` | ANALYST | Sandbox mode: put every switch back to its default |

"ANALYST" means ANALYST or ADMIN.
