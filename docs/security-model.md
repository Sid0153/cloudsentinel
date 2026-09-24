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
- Roles: ADMIN (everything, user management), ANALYST (will run scans and triage findings),
  VIEWER (read only). Today the only role-restricted endpoints are the ADMIN-only `/api/users`
  routes; the ANALYST tier is verified with a test route until scan endpoints exist.
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
- Audit logging of these events arrives in Phase 8 (events are only written to the app log now).
