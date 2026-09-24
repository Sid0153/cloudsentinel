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
| 5 Security rule engine | NEXT. Wait for the user to say "Proceed to Phase 5" |

Design decisions for the remaining phases are in `docs/architecture.md` and
`docs/security-model.md` (rule engine: pure Python rules in `backend/app/rules/`, metadata in
`security-rules/rules/*.yaml`, findings de-duplicated by fingerprint, "unknown" coverage must
never produce a clean result; risk engine: deterministic 0-100 score from severity, exposure,
impact and confidence with a stored breakdown).

## Environment (Windows)

- Python 3.12: `py -3.12`. Backend venv: `backend\.venv` (`.venv\Scripts\activate`).
- Node 24, npm. Docker Desktop must be running for PostgreSQL.
- Test database: `docker compose up -d db`, database `cloudsentinel_test`. Use `127.0.0.1`,
  not `localhost`, in `TEST_DATABASE_URL` (localhost tries IPv6 first and makes every new
  connection ~2 s slower on this machine).
- Never commit `.env`. Never ask for or store AWS credentials; the app uses the standard
  AWS credential chain.

## Checks before every commit

Backend (from `backend/`): `ruff check .`, `mypy`, `pytest` (with TEST_DATABASE_URL set).
Frontend (from `frontend/`): `npm test`, `npm run typecheck`, `npm run build`.
CI (`.github/workflows/ci.yml`) runs the same plus a Docker Compose smoke test; confirm it is
green after pushing.

## Conventions

- `aws/` is the only package importing boto3; `domain/`, `rules/` and `risk/` stay pure.
- Readable code over clever code, small modules, few dependencies.
- Tests: moto for AWS (it does not load AWS-managed policies and does not implement
  GetBucketPolicyStatus; tests use the `policy_status` fixture), real PostgreSQL for API tests.
- Every new API route must be added to `EXPECTED_ACCESS` or `PUBLIC_ROUTES` in
  `backend/tests/api/test_rbac.py`.
