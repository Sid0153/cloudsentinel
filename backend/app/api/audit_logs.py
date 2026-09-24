import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, Response

from app.api.deps import TOTAL_COUNT_HEADER, DbSession
from app.audit.events import AuditAction, AuditOutcome, TargetType
from app.audit.service import AuditFilters, list_audit_logs
from app.auth.deps import AdminUser
from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogPublic

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditLogPublic])
def list_all_audit_logs(
    _admin: AdminUser,
    db: DbSession,
    response: Response,
    action: Annotated[list[AuditAction] | None, Query()] = None,
    outcome: AuditOutcome | None = None,
    actor_id: uuid.UUID | None = None,
    target_type: TargetType | None = None,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditLog]:
    """Security-relevant events, newest first. ADMIN only. Read-only: there is no route (and,
    in the database, no permission) to change or delete an event."""
    filters = AuditFilters(
        actions=action,
        outcome=outcome,
        actor_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        since=since,
        until=until,
    )
    entries, total = list_audit_logs(db, filters, limit, offset)
    response.headers[TOTAL_COUNT_HEADER] = str(total)
    return entries
