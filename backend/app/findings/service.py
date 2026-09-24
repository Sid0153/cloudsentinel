"""Reading findings and recording analyst decisions."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, TargetType
from app.audit.service import record
from app.domain.resources import ResourceType
from app.models.finding import Finding, FindingStatus
from app.models.user import User
from app.rules.model import Category, Severity

SortField = Literal[
    "risk", "severity", "last_detected", "first_detected", "rule_id", "resource_id"
]
SortOrder = Literal["asc", "desc"]

# Sort severity by rank, not alphabetically. Unknown values sort lowest.
_SEVERITY_RANK = case(
    {str(severity): severity.rank for severity in Severity}, value=Finding.severity, else_=0
)


@dataclass(frozen=True)
class FindingFilters:
    aws_account_id: uuid.UUID | None = None
    resource_uuid: uuid.UUID | None = None
    statuses: list[FindingStatus] | None = None
    severities: list[Severity] | None = None
    categories: list[Category] | None = None
    resource_type: ResourceType | None = None
    rule_id: str | None = None
    region: str | None = None
    search: str | None = None  # matched against title, rule ID and resource ID
    min_risk: int | None = None


def _escape_like(text: str) -> str:
    """Treat %, _ and \\ in user input as plain characters in a LIKE pattern."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _apply_filters(statement: Select[Any], filters: FindingFilters) -> Select[Any]:
    if filters.aws_account_id is not None:
        statement = statement.where(Finding.aws_account_id == filters.aws_account_id)
    if filters.resource_uuid is not None:
        statement = statement.where(Finding.resource_uuid == filters.resource_uuid)
    if filters.statuses:
        statement = statement.where(Finding.status.in_(filters.statuses))
    if filters.severities:
        statement = statement.where(Finding.severity.in_([str(s) for s in filters.severities]))
    if filters.categories:
        statement = statement.where(Finding.category.in_([str(c) for c in filters.categories]))
    if filters.resource_type is not None:
        statement = statement.where(Finding.resource_type == str(filters.resource_type))
    if filters.rule_id is not None:
        statement = statement.where(Finding.rule_id == filters.rule_id)
    if filters.region is not None:
        statement = statement.where(Finding.region == filters.region)
    if filters.min_risk is not None:
        statement = statement.where(Finding.risk_score >= filters.min_risk)
    if filters.search:
        pattern = f"%{_escape_like(filters.search)}%"
        statement = statement.where(
            or_(
                Finding.title.ilike(pattern, escape="\\"),
                Finding.rule_id.ilike(pattern, escape="\\"),
                Finding.resource_id.ilike(pattern, escape="\\"),
            )
        )
    return statement


def list_findings(
    db: Session,
    filters: FindingFilters,
    sort: SortField = "risk",
    order: SortOrder = "desc",
    limit: int = 100,
    offset: int = 0,
) -> list[Finding]:
    columns = {
        "risk": Finding.risk_score,
        "severity": _SEVERITY_RANK,
        "last_detected": Finding.last_detected,
        "first_detected": Finding.first_detected,
        "rule_id": Finding.rule_id,
        "resource_id": Finding.resource_id,
    }
    column = columns[sort]
    # Unscored findings (NULL risk) always sort last.
    primary = column.desc().nulls_last() if order == "desc" else column.asc().nulls_last()
    # Secondary keys make the order (and therefore pagination) stable.
    statement = _apply_filters(select(Finding), filters).order_by(
        primary, Finding.last_detected.desc(), Finding.id
    )
    return list(db.scalars(statement.limit(limit).offset(offset)))


def count_findings(db: Session, filters: FindingFilters) -> int:
    statement = _apply_filters(select(func.count()).select_from(Finding), filters)
    return int(db.scalar(statement) or 0)


def update_finding_status(
    db: Session,
    finding: Finding,
    status: FindingStatus,
    note: str | None,
    actor: User,
) -> Finding:
    now = datetime.now(UTC)
    previous = finding.status
    finding.status = status
    finding.status_note = note
    finding.status_updated_at = now
    finding.status_updated_by_id = actor.id
    finding.resolved_at = now if status == FindingStatus.RESOLVED else None
    # The note stays on the finding; the audit record only says whether one was given.
    record(
        db,
        AuditAction.FINDING_STATUS_CHANGED,
        actor=actor,
        target_type=TargetType.FINDING,
        target_id=finding.id,
        details={
            "rule_id": finding.rule_id,
            "resource_id": finding.resource_id,
            "from": str(previous),
            "to": str(status),
            "note_provided": bool(note),
        },
    )
    db.commit()
    return finding
