# CloudSentinel

An AWS cloud security monitoring and misconfiguration detection platform (portfolio project).

> **Status: Phase 3 of 10 (authentication and RBAC).** Login, roles and protected routes exist.
> There is **no AWS integration, rule engine or dashboard yet**. Those arrive in later phases; this README will be rewritten in
> Phase 10 and will only describe what is actually implemented.

## What exists today

- FastAPI backend with `/api/health/live` and `/api/health/ready` (the latter checks PostgreSQL)
- Settings validated at startup (missing or short `SECRET_KEY` stops the app)
- Log redaction (passwords, tokens, AWS key IDs), request IDs, security headers, generic 500 errors
- SQLAlchemy + Alembic wired to PostgreSQL, with an empty baseline migration
- React + TypeScript + Vite + Tailwind frontend showing the live readiness result
- Docker Compose stack: PostgreSQL, backend, frontend (nginx)
- Authentication: Argon2id passwords, 15-minute access tokens, rotating httpOnly refresh cookie,
  account lockout and login rate limiting (details: `docs/security-model.md`)
- Roles ADMIN / ANALYST / VIEWER enforced on the server, with a test that every route has an
  access rule
- Frontend: login page, protected routes, admin-only Users page

## Run with Docker

```bash
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD and SECRET_KEY (commands are in the file)
docker compose up --build
```

- Frontend: http://localhost:8080
- API docs (backend directly): http://localhost:8000/api/docs
- Readiness: http://localhost:8000/api/health/ready

**Create the first administrator** (there is no public sign-up):

```bash
docker compose exec backend python -m app.cli create-admin --email you@example.com
```

It asks for a password (12 to 128 characters) without showing it. Then sign in at
http://localhost:8080.

To wipe the database (for example after changing `POSTGRES_PASSWORD`): `docker compose down -v`.

## Run tests

Backend (from `backend/`):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest   # database-backed tests are skipped unless TEST_DATABASE_URL is set
# full suite against a scratch PostgreSQL database (tables are created and dropped):
TEST_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@localhost:5432/scratch_db pytest
ruff check . && mypy
```

Frontend (from `frontend/`):

```bash
npm install
npm test
npm run typecheck
npm run build
```

## Local development without Docker

Start only the database (`docker compose up db`), then in `backend/` set `DATABASE_URL` and
`SECRET_KEY` in your environment (or a `backend/.env`), run
`alembic upgrade head`, then `uvicorn app.main:create_app --factory --reload`.
In `frontend/`, `npm run dev` serves on http://localhost:5173 and proxies `/api` to port 8000.

## Repository layout

```
backend/    FastAPI app (app/), Alembic migrations (alembic/), tests (tests/)
frontend/   React + TypeScript + Vite + Tailwind (src/), tests (tests/)
docs/       Architecture notes
docker-compose.yml, .env.example
```
