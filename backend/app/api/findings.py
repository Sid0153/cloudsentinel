import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.api.deps import TOTAL_COUNT_HEADER, DbSession
from app.auth.deps import AnalystUser, CurrentUser
from app.domain.resources import ResourceType
from app.findings.service import (
    FindingFilters,
    SortField,
    SortOrder,
    count_findings,
    list_findings,
    update_finding_status,
)
from app.models.finding import Finding, FindingStatus
from app.models.resource import Resource
from app.rules.model import Category, Severity
from app.schemas.finding import FindingDetail, FindingStatusUpdate, FindingSummary, RulePublic
from app.services.rule_catalog import get_rule_catalog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingSummary])
def list_all_findings(
    _user: CurrentUser,
    db: DbSession,
    response: Response,
    aws_account_id: uuid.UUID | None = None,
    resource_uuid: uuid.UUID | None = None,
    finding_status: Annotated[list[FindingStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    category: Annotated[list[Category] | None, Query()] = None,
    resource_type: ResourceType | None = None,
    rule_id: Annotated[str | None, Query(max_length=32)] = None,
    region: Annotated[str | None, Query(max_length=32)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    min_risk: Annotated[int | None, Query(ge=0, le=100)] = None,
    sort: SortField = "risk",
    order: SortOrder = "desc",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Finding]:
    """Findings, highest risk first by default. Repeat status / severity / category to match
    any of several values, e.g. ?severity=HIGH&severity=CRITICAL. The X-Total-Count header
    holds the number of matching findings (for pagination)."""
    filters = FindingFilters(
        aws_account_id=aws_account_id,
        resource_uuid=resource_uuid,
        statuses=finding_status,
        severities=severity,
        categories=category,
        resource_type=resource_type,
        rule_id=rule_id,
        region=region,
        search=q.strip() if q else None,
        min_risk=min_risk,
    )
    response.headers[TOTAL_COUNT_HEADER] = str(count_findings(db, filters))
    return list_findings(db, filters, sort, order, limit, offset)


def _get_or_404(db: DbSession, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


def _detail(db: DbSession, finding: Finding) -> FindingDetail:
    resource = db.get(Resource, finding.resource_uuid)
    rule = get_rule_catalog().get(finding.rule_id)
    return FindingDetail.model_validate(finding).model_copy(
        update={
            "resource_name": resource.name if resource else None,
            "rule": RulePublic.from_rule(rule) if rule else None,
        }
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> FindingDetail:
    """One finding with its evidence, the rule's explanation and remediation steps."""
    return _detail(db, _get_or_404(db, finding_id))


@router.patch("/{finding_id}", response_model=FindingDetail)
def change_finding_status(
    finding_id: uuid.UUID, payload: FindingStatusUpdate, user: AnalystUser, db: DbSession
) -> FindingDetail:
    """Triage a finding. FALSE_POSITIVE needs a note. A scan that detects a RESOLVED finding
    again reopens it; ACKNOWLEDGED and FALSE_POSITIVE are kept."""
    finding = _get_or_404(db, finding_id)
    previous = finding.status
    update_finding_status(db, finding, payload.status, payload.note, user)
    # Also in the audit log (FINDING_STATUS_CHANGED); the note itself is not logged.
    logger.info(
        "Finding %s status changed from %s to %s by user %s",
        finding.id,
        previous,
        finding.status,
        user.id,
    )
    return _detail(db, finding)
