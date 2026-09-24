import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.core.rate_limit import SlidingWindowRateLimiter
from app.services.rule_catalog import get_rule_catalog

logger = logging.getLogger(__name__)

API_DESCRIPTION = """
Read-only AWS security scanning: discover resources, evaluate security rules, score risk.

**Authentication.** `POST /api/auth/login` returns a short-lived access token; send it as
`Authorization: Bearer <token>`. A refresh token is set as an httpOnly cookie and exchanged at
`POST /api/auth/refresh`. Roles: VIEWER (read), ANALYST (+ scans and triage), ADMIN (+ users,
AWS accounts, audit log). The role a route needs is in its description and in docs/api.md.

**Lists** return one page (`limit`, `offset`); the `X-Total-Count` header holds the total.

**Errors** have a `detail` field. Validation errors (422) never echo the submitted values.
"""

OPENAPI_TAGS = [
    {"name": "health", "description": "Liveness and readiness checks (no sign-in needed)."},
    {"name": "auth", "description": "Sign in, refresh and end sessions, change your password."},
    {"name": "users", "description": "User administration (ADMIN)."},
    {"name": "aws-accounts", "description": "AWS accounts to scan. No credentials are stored."},
    {"name": "scans", "description": "Start read-only scans and follow their progress."},
    {"name": "resources", "description": "AWS resources found by scans."},
    {"name": "findings", "description": "Security findings: filter, read, triage (ANALYST+)."},
    {"name": "rules", "description": "The security rules every scan runs."},
    {"name": "dashboard", "description": "Summary numbers for the dashboard."},
    {"name": "audit", "description": "Append-only log of security-relevant actions (ADMIN)."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("CloudSentinel API starting (version %s)", __version__)
    yield
    logger.info("CloudSentinel API stopping")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Run with: uvicorn app.main:create_app --factory"""
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    # Fail at startup, not during the first scan, if the rule catalog is broken.
    catalog = get_rule_catalog()
    logger.info("Loaded %d security rules", len(catalog.rules))

    app = FastAPI(
        title="CloudSentinel API",
        version=__version__,
        description=API_DESCRIPTION,
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.docs_enabled else None,
        openapi_url="/api/openapi.json" if settings.docs_enabled else None,
        redoc_url=None,
    )

    # Middleware added last is outermost, so request-ID/security headers wrap CORS responses too.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],  # the API has no PUT or DELETE routes
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(RequestContextMiddleware)

    # One limiter per app instance (so tests are isolated); keyed by client IP.
    app.state.login_limiter = SlidingWindowRateLimiter(settings.login_rate_limit_per_minute)

    register_exception_handlers(app)
    app.include_router(api_router, prefix="/api")
    return app
