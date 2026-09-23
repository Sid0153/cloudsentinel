# CloudSentinel

An AWS cloud security monitoring and misconfiguration detection platform (portfolio project).

> **Status: Phase 2 of 10 (foundation).** The repository, backend skeleton, frontend skeleton,
> database migrations and Docker setup exist. There is **no AWS integration, authentication,
> rule engine or dashboard yet**. Those arrive in later phases; this README will be rewritten in
> Phase 10 and will only describe what is actually implemented.

## What exists today

- FastAPI backend with `/api/health/live` and `/api/health/ready` (the latter checks PostgreSQL)
- Settings validated at startup (missing or short `SECRET_KEY` stops the app)
- Log redaction (passwords, tokens, AWS key IDs), request IDs, security headers, generic 500 errors
- SQLAlchemy + Alembic wired to PostgreSQL, with an empty baseline migration
- React + TypeScript + Vite + Tailwind frontend showing the live readiness result
- Docker Compose stack: PostgreSQL, backend, frontend (nginx)

## Run with Docker

```bash
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD and SECRET_KEY (commands are in the file)
docker compose up --build
```

- Frontend: http://localhost:8080
- API docs (backend directly): http://localhost:8000/api/docs
- Readiness: http://localhost:8000/api/health/ready

To wipe the database (for example after changing `POSTGRES_PASSWORD`): `docker compose down -v`.

## Run tests

Backend (from `backend/`):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                                   # unit tests, no database needed
# migration test against a scratch PostgreSQL database:
TEST_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@localhost:5432/scratch_db pytest -m integration
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
