import uuid

from pydantic import BaseModel, ConfigDict

from app.risk.model import Priority
from app.schemas.finding import FindingSummary
from app.schemas.scan import ScanPublic


class OverallRiskPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    score: int  # the highest risk score among open findings
    priority: Priority
    finding_id: uuid.UUID  # the finding that sets it


class DashboardSummary(BaseModel):
    """Counts cover open findings (OPEN or ACKNOWLEDGED) unless the name says otherwise."""

    model_config = ConfigDict(from_attributes=True)

    aws_account_count: int
    resource_count: int
    resources_by_type: dict[str, int]
    open_finding_count: int
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]
    findings_by_priority: dict[str, int]  # scored findings only
    findings_by_status: dict[str, int]  # all findings, every status
    overall_risk: OverallRiskPublic | None  # None when there are no open scored findings
    latest_scan: ScanPublic | None
    top_risks: list[FindingSummary]
