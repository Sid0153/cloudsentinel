# Architecture (foundation)

CloudSentinel is a modular monolith: one FastAPI service, one React single-page app, one
PostgreSQL database.

```
Browser ──► nginx (frontend container) ──/api──► FastAPI ──► PostgreSQL
                                                    │
                                                    └──► AWS APIs (read-only, from Phase 4)
```

## Dependency direction (enforced by convention and, later, by review)

```
api  →  services  →  aws / rules / risk / audit  →  domain
                  ↓
             models + database
```

- `rules/` and `risk/` (Phases 5-6) will be pure Python: no boto3, no database, no network.
- `aws/` (Phase 4) is the only package that will import boto3.

## Decisions made so far

| Decision | Why |
|---|---|
| Modular monolith | One deployable unit is enough; separation comes from packages |
| Synchronous SQLAlchemy and route handlers | boto3 is synchronous; simpler to read and debug |
| Settings via environment, no secret defaults | A misconfigured deployment fails at startup |
| Application factory (`create_app`) | Tests can build an app with custom settings |
| Alembic from the first phase | Schema changes are versioned from day one |
| API served under `/api`, same origin via nginx | No CORS in the Docker setup; simpler cookie handling later |
