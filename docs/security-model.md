# Security model: authentication and authorization (Phase 3)

## Accounts

- There is **no public registration**. The first ADMIN is created on the server with
  `python -m app.cli create-admin --email you@example.com` (hidden password prompt). After
  that, admins create users through `POST /api/users` or the Users page.
- Passwords are hashed with **Argon2id** (`argon2-cffi` defaults). Length policy only:
  12 to 128 characters, no forced symbols.
- Emails are trimmed and lowercased before storage and lookup.

## Sessions

| Token | Lifetime | Where it lives | Purpose |
|---|---|---|---|
| Access token (JWT, HS256) | 15 minutes | JavaScript memory only | Sent as `Authorization: Bearer` |
| Refresh token (random, 384 bits) | 7 days | `httpOnly`, `SameSite=Strict` cookie scoped to `/api/auth` | Gets a new access token |

- Only a SHA-256 hash of each refresh token is stored (`refresh_tokens`).
- Refresh tokens are **rotated** on every use. Presenting one that was already used is treated
  as theft and revokes every session of that user.
- Logout, password change and user deactivation revoke refresh tokens server-side.
- The access token contains only the user ID. The **role is read from the database on every
  request**, so demotion or deactivation takes effect immediately.
- The signing algorithm is pinned on decode, and `iss`, `exp`, `iat`, `sub` and `typ` are required.
- The `Secure` cookie flag is enabled when `APP_ENV=production`.

## Login hardening

- Same `401 Invalid email or password` for unknown email, wrong password, locked and disabled
  accounts. A dummy Argon2 check runs for unknown emails so timing does not reveal them.
- Account lockout: 5 consecutive failures lock the account for 15 minutes.
- Per-IP rate limit on login: 10 attempts per minute, then `429` with `Retry-After`.
- Failed logins are logged with the client IP only, never the submitted email or password.
- Validation errors never echo submitted values (a custom 422 handler strips them).

## Authorization

- Every protected route depends on `get_current_user`; role checks use `require_role(...)`.
- Roles: ADMIN (everything: users, AWS account registration and verification), ANALYST
  (starts scans; triages findings), VIEWER (read only: accounts, scans, resources, findings,
  rules).
- `tests/api/test_rbac.py` fails if any route lacks a declared access rule, and runs every
  protected route against every role.
- Frontend route guards are a convenience only. The API is the enforcement point.

## Known limitations

- The rate limiter and lockout counters protect one backend instance. Scaling out would need a
  shared store.
- A legitimate double refresh (two tabs refreshing in the same instant) can be mistaken for
  token replay and sign the user out. The frontend shares a single in-flight refresh per tab
  to avoid this, but two tabs can still collide.
- There is no email verification, password reset flow or MFA yet.
- Security events (logins, lockouts, logouts, password changes, token reuse, access denied,
  user and AWS account changes, scans, finding triage) are written to the append-only audit log;
  see "Audit log" in `docs/architecture.md`. Passwords, tokens and the email typed into a failed
  login are never stored, and a finding's note stays on the finding.
- Scans run as background tasks inside the API process. A restart loses a running scan; the
  container entrypoint marks such scans FAILED on the next start. This assumes one backend
  instance.

## AWS access

- No AWS credential is ever stored in the database, the repository or the UI. The backend
  uses boto3's standard credential chain; see `docs/aws-permissions.md`.
- Every scan first calls `sts:GetCallerIdentity` and refuses to continue if the credentials
  belong to a different account than the one registered.
- The code only reads configuration. The two calls that are not plain reads change no
  resources: `iam:GenerateCredentialReport` (asks AWS to build the report) and the optional
  `sts:AssumeRole`. The recommended IAM policy grants 14 actions.
- Error messages stored with a scan contain only the AWS error code and operation name
  (e.g. `AccessDenied (GetBucketAcl)`), never AWS's full message, which can contain ARNs.
- The test suite replaces credentials with fake values and uses moto, so tests can never
  reach a real AWS account.

## Rule engine and findings

- Rule metadata is loaded with `yaml.safe_load`, which builds only plain data; a rule file cannot
  run code (tested with a `!!python/object` payload).
- Evidence is copied from the normalized configuration only (ports, CIDR ranges, grant names,
  policy statement sources). No credentials, access key IDs or policy documents are stored in
  findings; the credential report's root-account row is never collected.
- Finding filters are bound parameters. The search text is escaped so `%` and `_` are literal,
  and `sort` / `order` accept only a fixed list of values (anything else is a 422).
- Only ANALYST and ADMIN can change a finding's status; VIEWER is read-only
  (enforced by `require_role`, covered by `test_rbac.py`).
