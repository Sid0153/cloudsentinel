# CloudSentinel: instructions for Claude Code

Read `CLOUDSENTINEL_MASTER_PROMPT.md` first. It is the project brief and its rules always apply:
phase-by-phase work, stop after each phase, report ACTUAL test results, label everything
IMPLEMENTED / TESTED / MOCKED / PARTIALLY IMPLEMENTED / NOT IMPLEMENTED, never claim
something works without verifying it, and end each phase with the interview-learning section.

## Current state

| Phase | Status |
|---|---|
| 1 Architecture | Done |
| 2 Foundation | Done, green in CI |
| 3 Authentication and RBAC | Done, green in CI |
| 4 AWS integration | Done, green in CI (190 backend tests). Real-AWS scan not yet tried |
| 5 Security rule engine | Done, green in CI (334 backend tests). 8 rules, findings API |
| 6 Risk engine | Done, green in CI (378 backend tests). docs/risk-model.md |
| 7 Dashboard | Done, green in CI (387 backend, 53 frontend tests). Visually checked desktop + phone |
| 8 Audit logging | Done, green in CI (410 backend, 58 frontend tests). Append-only via DB triggers |
| 9 Quality / DevOps | Done, green in CI (421 backend tests, 96% coverage, 0 audit findings, gitleaks clean) |
| 10 Portfolio preparation | NEXT. Wait for the user to say "Proceed to Phase 10" |

Design decisions are in `docs/architecture.md` and `docs/security-model.md`. Rule engine
(Phase 5): checks in `backend/app/rules/checks/`, listed in `registry.py`, metadata in
`security-rules/rules/*.yaml`; outcomes PASS / FAIL / UNKNOWN; findings de-duplicated by
fingerprint and closed only when a scan proves the problem is gone (UNKNOWN never closes one).
Risk engine (Phase 6, `docs/risk-model.md`): score = severity + exposure + impact + confidence
points, a pure function of (rule, resource type, severity, evidence); anything it needs must be
in the evidence. Every rule needs a profile in `backend/app/risk/profiles.py`; changing a weight
means bumping `RISK_MODEL_VERSION`.

## Environment (Windows)

- Python 3.12: `py -3.12`. Backend venv: `backend\.venv` (`.venv\Scripts\activate`).
- Node 24, npm. Docker Desktop must be running for PostgreSQL.
- Test database: `docker compose up -d db`, database `cloudsentinel_test`. Use `127.0.0.1`,
  not `localhost`, in `TEST_DATABASE_URL` (localhost tries IPv6 first and makes every new
  connection ~2 s slower on this machine).
- Never commit `.env`. Never ask for or store AWS credentials; the app uses the standard
  AWS credential chain.

## Checks before every commit

Backend (from `backend/`): `ruff check .`, `mypy`, `pytest --cov=app` (with TEST_DATABASE_URL
set; CI fails under 90% coverage), `pip-audit -r requirements.txt --require-hashes --disable-pip`.
Frontend (from `frontend/`): `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`,
`npm audit --audit-level=moderate`.
CI (`.github/workflows/ci.yml`) runs the same plus gitleaks and a Docker Compose smoke test
(including hardening checks); confirm it is green after pushing.
After changing an API route or schema: `python -m app.cli export-openapi` (from `backend/`) and
update the table in `docs/api.md`; tests fail if either is stale.

## Conventions

- `aws/` is the only package importing boto3; `domain/`, `rules/` and `risk/` stay pure.
- Readable code over clever code, small modules, few dependencies.
- Tests: moto for AWS (it does not load AWS-managed policies and does not implement
  GetBucketPolicyStatus; tests use the `policy_status` fixture), real PostgreSQL for API tests.
- Security-relevant actions call `app.audit.service.record()` before the commit that saves the
  change (same transaction). Never put secrets in `details`. `audit_logs` is append-only (DB
  triggers): tests must not try to clean it up with DELETE.
- Every new API route must be added to `EXPECTED_ACCESS` or `PUBLIC_ROUTES` in
  `backend/tests/api/test_rbac.py`.
- New rules need a check, a `registry.py` entry, a YAML file, a risk profile and tests (see
  `security-rules/README.md`); the app refuses to start if they do not match.
- The backend image gets `security-rules/` through the compose build context `security_rules`.
- Frontend: API calls live in `src/services/`, types mirror backend schemas in `src/types/api.ts`,
  pages load data with `useApi`. Tests render the whole app with `tests/renderApp.tsx` and mock
  `fetch` per route (`tests/mockApi.ts`; `PENDING` keeps a request open for loading states).
- Dependencies are locked. Backend: edit `requirements*.in`, then run the `uv pip compile`
  command at the top of the `.txt` lockfile; install with `pip install --require-hashes`.
  Frontend: `npm ci`; `package-lock.json` is committed. Never silence an audit finding without
  saying why; upgrade instead.
- In Git Bash, `docker run -v` paths need `MSYS_NO_PATHCONV=1`.
