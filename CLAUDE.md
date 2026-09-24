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
| 6 Risk engine | Done locally; not yet pushed to CI |
| 7 Dashboard | NEXT. Wait for the user to say "Proceed to Phase 7" |

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
- New rules need a check, a `registry.py` entry, a YAML file, a risk profile and tests (see
  `security-rules/README.md`); the app refuses to start if they do not match.
- The backend image gets `security-rules/` through the compose build context `security_rules`.
- Frontend has no committed lockfile yet: run `npm install` first, and do not commit the
  generated `package-lock.json` (planned for Phase 9).
