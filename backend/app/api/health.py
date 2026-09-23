import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.health import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=HealthResponse)
def live() -> HealthResponse:
    """Liveness: the process is up. Never touches the database."""
    return HealthResponse(status="ok")


@router.get("/ready", response_model=HealthResponse)
def ready(response: Response, db: Annotated[Session, Depends(get_db)]) -> HealthResponse:
    """Readiness: the app can serve requests, which requires a reachable database."""
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.exception("Readiness check failed: database unreachable")
        response.status_code = 503
        return HealthResponse(status="unavailable", database="down")
    return HealthResponse(status="ok", database="up")
