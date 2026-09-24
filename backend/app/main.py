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
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(RequestContextMiddleware)

    # One limiter per app instance (so tests are isolated); keyed by client IP.
    app.state.login_limiter = SlidingWindowRateLimiter(settings.login_rate_limit_per_minute)

    register_exception_handlers(app)
    app.include_router(api_router, prefix="/api")
    return app
