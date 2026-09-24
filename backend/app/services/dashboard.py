"""Numbers for the dashboard, computed from the current findings and resources.

"Open" means a finding still needs attention: OPEN or ACKNOWLEDGED. RESOLVED and
FALSE_POSITIVE findings are left out of every count except findings_by_status.
"""

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models.aws_account import AwsAccount
from app.models.finding import ACTIVE_FINDING_STATUSES, Finding, FindingStatus
from app.models.resource import Resource
from app.models.scan import Scan
from app.risk.model import Priority, priority_for
from app.rules.model import Category, Severity

TOP_RISKS = 5


@dataclass(frozen=True)
class OverallRisk:
    score: int
    priority: Priority
    finding_id: uuid.UUID


@dataclass(frozen=True)
class DashboardData:
    aws_account_count: int
    resource_count: int
    resources_by_type: dict[str, int]
    open_finding_count: int
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]
    findings_by_priority: dict[str, int]
    findings_by_status: dict[str, int]
    overall_risk: OverallRisk | None
    latest_scan: Scan | None
    top_risks: list[Finding]


def _counts(db: Session, statement: Select[Any]) -> dict[str, int]:
    return {str(key): int(count) for key, count in db.execute(statement).all()}


def _with_zeros(counts: dict[str, int], keys: list[str]) -> dict[str, int]:
    """Every expected key present (0 if missing), so charts always show every category."""
    return {key: counts.get(key, 0) for key in keys}


def build_dashboard(db: Session, aws_account_id: uuid.UUID | None = None) -> DashboardData:
    def for_account(statement: Select[Any], column: Any) -> Select[Any]:
        return statement if aws_account_id is None else statement.where(column == aws_account_id)

    def open_findings(statement: Select[Any]) -> Select[Any]:
        statement = statement.where(Finding.status.in_(ACTIVE_FINDING_STATUSES))
        return for_account(statement, Finding.aws_account_id)

    by_severity = _counts(
        db, open_findings(select(Finding.severity, func.count()).group_by(Finding.severity))
    )
    by_category = _counts(
        db, open_findings(select(Finding.category, func.count()).group_by(Finding.category))
    )
    all_statuses = for_account(
        select(Finding.status, func.count()).group_by(Finding.status), Finding.aws_account_id
    )
    by_status = _counts(db, all_statuses)
    by_type = _counts(
        db,
        for_account(
            select(Resource.resource_type, func.count()).group_by(Resource.resource_type),
            Resource.aws_account_id,
        ),
    )
    scores = db.scalars(
        open_findings(select(Finding.risk_score).where(Finding.risk_score.is_not(None)))
    ).all()
    by_priority: dict[str, int] = {str(p): 0 for p in Priority}
    for score in scores:
        if score is not None:
            by_priority[str(priority_for(score))] += 1

    top_risks = list(
        db.scalars(
            open_findings(select(Finding))
            .where(Finding.risk_score.is_not(None))
            .order_by(Finding.risk_score.desc(), Finding.last_detected.desc(), Finding.id)
            .limit(TOP_RISKS)
        )
    )
    overall = None
    if top_risks and top_risks[0].risk_score is not None:
        worst = top_risks[0]
        score = int(worst.risk_score or 0)
        overall = OverallRisk(score=score, priority=priority_for(score), finding_id=worst.id)

    latest_scan = db.scalar(
        for_account(select(Scan), Scan.aws_account_id)
        .order_by(Scan.created_at.desc(), Scan.id)
        .limit(1)
    )
    account_count = db.scalar(
        for_account(select(func.count()).select_from(AwsAccount), AwsAccount.id)
    )

    return DashboardData(
        aws_account_count=int(account_count or 0),
        resource_count=sum(by_type.values()),
        resources_by_type=by_type,
        open_finding_count=sum(by_severity.values()),
        findings_by_severity=_with_zeros(by_severity, [str(s) for s in Severity]),
        findings_by_category=_with_zeros(by_category, [str(c) for c in Category]),
        findings_by_priority=by_priority,
        findings_by_status=_with_zeros(by_status, [str(s) for s in FindingStatus]),
        overall_risk=overall,
        latest_scan=latest_scan,
        top_risks=top_risks,
    )
