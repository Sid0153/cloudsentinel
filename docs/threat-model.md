# Threat model

Scope: CloudSentinel as shipped in this repository (Docker Compose: nginx + FastAPI +
PostgreSQL), scanning AWS accounts read-only. Method: list what is worth protecting, where
trust changes, then go through STRIDE (spoofing, tampering, repudiation, information
disclosure, denial of service, elevation of privilege). Each mitigation names where it is
implemented or tested; the last section lists what is **not** mitigated.

## Assets

| Asset | Why it matters |
|---|---|
| AWS read access (the backend's AWS identity) | Reveals the whole security posture of the account |
| Findings and resource inventory | A map of weaknesses: exactly what an attacker wants |
| User accounts and sessions | Access to the above; ANALYST/ADMIN can change state |
| Audit log | Evidence of who did what; worthless if it can be edited |
| `SECRET_KEY`, database password | Forge tokens / read everything |

## Trust boundaries

```
Browser ──(1)── nginx ──(2)── FastAPI ──(3)── PostgreSQL
                                  └────(4)── AWS APIs (read-only identity)
Operator shell ──(5)── containers (.env, CLI)
```

1. Internet/user to the app: untrusted input, stolen sessions, brute force.
2. nginx to backend: `X-Forwarded-For` is trusted from nginx only (backend port bound to localhost).
3. Backend to database: the application's database user can read and write everything except
   change or delete audit records.
4. Backend to AWS: responses are data; errors can contain ARNs.
5. Operator: configuration and secrets.

## STRIDE

| Threat | Example | Mitigation | Where |
|---|---|---|---|
| **Spoofing** | Password guessing | Argon2id, 12+ character passwords, per-IP rate limit (10/min), lockout after 5 failures, same error for every failure | `auth/service.py`, `tests/api/test_auth.py` |
| Spoofing | Stolen refresh token | httpOnly `SameSite=Strict` cookie scoped to `/api/auth`, rotation on every use, reuse revokes all sessions (and is audited) | `auth/service.py`, `test_auth.py`, `test_audit.py` |
| Spoofing | Forged access token | HS256 with a validated random key, algorithm pinned, `exp/iat/iss/sub/typ` required, role re-read from the database on every request | `auth/tokens.py`, `core/config.py` |
| Spoofing | Scanning the wrong AWS account | `sts:GetCallerIdentity` must match the registered account ID or the scan stops | `scans/service.py`, `test_scans.py` |
| **Tampering** | SQL injection via filters or search | SQLAlchemy bound parameters, `LIKE` wildcards escaped, `sort`/`order` from a fixed list | `findings/service.py`, `test_findings.py` |
| Tampering | Editing the audit trail | Database triggers reject UPDATE, DELETE, TRUNCATE on `audit_logs` | migration 0006, `test_audit.py` |
| Tampering | Malicious rule file | `yaml.safe_load`, strict schema, startup refuses mismatches | `rules/catalog.py`, `test_rule_catalog.py` |
| Tampering | Compromised dependency | Hash-pinned lockfiles installed with `--require-hashes`, `npm ci`, pip-audit / npm audit in CI, Dependabot | `requirements*.txt`, CI |
| **Repudiation** | "I did not change that" | Append-only audit log with actor, IP and request ID for logins, admin actions, scans and triage | `audit/`, `docs/architecture.md` |
| **Information disclosure** | Secrets in logs or errors | Log redaction filter, 422 bodies without submitted values, generic 500s, settings errors without values, audit sanitizer | `core/redaction.py`, `core/errors.py`, `test_config.py`, `test_audit_sanitize.py` |
| Information disclosure | AWS error text with ARNs | Only error code and operation are stored (`AccessDenied (GetBucketAcl)`) | `aws/common.py`, `test_scans.py` |
| Information disclosure | XSS stealing tokens | React escaping, evidence shown as text, no `dangerouslySetInnerHTML`, CSP `script-src 'self'`, access token in memory only | frontend, `nginx.conf`, `audit.test.tsx` |
| Information disclosure | Committed credentials | No AWS keys anywhere (standard credential chain), `.env` ignored, gitleaks over full history in CI | `.gitleaks.toml`, CI |
| Information disclosure | Over-privileged AWS identity | Custom 14-action read-only policy; a test proves it matches the code exactly | `infrastructure/`, `test_iam_policy.py` |
| **Denial of service** | Login flooding | Rate limit and lockout (per process) | `core/rate_limit.py` |
| Denial of service | Huge requests / pages | `limit` caps on lists, 1 MB body limit at nginx, string length limits in schemas | API, `nginx.conf` |
| Denial of service | Many parallel scans | One active scan per AWS account (row lock) | `scans/service.py`, `test_scans.py` |
| **Elevation of privilege** | VIEWER calling ANALYST/ADMIN routes | `require_role` on the server; a test enumerates every route and every role; denials are audited | `auth/deps.py`, `test_rbac.py` |
| Elevation of privilege | Admin locking themselves out / self-promotion | Admins cannot change their own role or active flag | `user_service.py`, `test_users.py` |
| Elevation of privilege | Container escape after an RCE | Non-root users, no capabilities, `no-new-privileges`, read-only root filesystem (checked in CI) | `docker-compose.yml`, CI |

## Residual risks (not mitigated)

- **No MFA for CloudSentinel users** and no password reset flow.
- **Single instance assumed:** rate-limit and lockout counters are in memory per process, and
  scans run as background tasks inside the API process (a restart fails running scans).
- **No TLS in the compose stack.** Production needs TLS termination in front of nginx; the
  refresh cookie is marked `Secure` only when `APP_ENV=production`.
- **The database user can still insert audit rows** (a compromised backend could add noise,
  though not erase history), and a database superuser can drop the triggers. Shipping the
  audit log off-host (SIEM/CloudWatch) is not implemented.
- **Frontend role checks are cosmetic;** safety relies on the API checks (tested).
- **Findings are only as good as the checks:** IAM analysis is pattern matching, attachments
  consider EC2 only, and several AWS services are not scanned at all (see the README).
- **Supply chain:** actions and base images are pinned by tag, not by digest; no image scan
  or SBOM.
- **Denial of service at scale** (many large accounts, huge IAM exports) was not load-tested.
