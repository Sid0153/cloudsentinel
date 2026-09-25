"""Per-client rate limits for actions that do work in the background or in the simulator."""

import logging

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditOutcome
from app.audit.service import record
from app.core.middleware import client_ip
from app.core.rate_limit import SlidingWindowRateLimiter
from app.models.user import User

logger = logging.getLogger(__name__)


def enforce_rate_limit(
    request: Request, db: Session, limiter: SlidingWindowRateLimiter, *, actor: User, kind: str
) -> None:
    """Raises 429 when this client IP used up its budget for `kind` (for example "scan").

    Keyed by IP, not by user: on a public demo many visitors share one guest account.
    """
    ip = client_ip(request)
    if limiter.allow(ip):
        return
    logger.warning("Rate limit for %s hit from %s", kind, ip)
    record(
        db,
        AuditAction.RATE_LIMITED,
        outcome=AuditOutcome.FAILURE,
        actor=actor,
        details={"limit": kind},
    )
    db.commit()
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Too many {kind} requests. Try again in a minute.",
        headers={"Retry-After": "60"},
    )
