import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    aws_account_id: uuid.UUID


class ScanPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    aws_account_id: uuid.UUID
    status: ScanStatus
    triggered_by_id: uuid.UUID | None
    caller_arn: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    resource_count: int
    resource_counts: dict[str, int]
    coverage: dict[str, Any]
    error_summary: str | None
    finding_count: int
    finding_counts: dict[str, int]  # findings detected by this scan, by severity
    risk_summary: dict[str, Any]  # max_score and counts per priority band (P1-P4)
    rule_results: dict[str, Any]  # per rule: status (PASSED, FAILED, INCOMPLETE...) and counts
