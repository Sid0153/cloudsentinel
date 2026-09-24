import uuid
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.finding import FindingStatus
from app.rules.model import Category, Rule, Severity


class ReferencePublic(BaseModel):
    title: str
    url: str


class RulePublic(BaseModel):
    id: str
    title: str
    category: Category
    severity: Severity
    resource_types: list[str]
    description: str
    rationale: str
    remediation: str
    severity_note: str | None
    limitations: str | None
    references: list[ReferencePublic]

    @classmethod
    def from_rule(cls, rule: Rule) -> "RulePublic":
        metadata = rule.metadata
        return cls(
            id=metadata.id,
            title=metadata.title,
            category=metadata.category,
            severity=metadata.severity,
            resource_types=[str(t) for t in rule.resource_types],
            description=metadata.description,
            rationale=metadata.rationale,
            remediation=metadata.remediation,
            severity_note=metadata.severity_note,
            limitations=metadata.limitations,
            references=[ReferencePublic(title=r.title, url=r.url) for r in metadata.references],
        )


class FindingSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    aws_account_id: uuid.UUID
    resource_uuid: uuid.UUID
    rule_id: str
    title: str
    category: Category
    severity: Severity
    status: FindingStatus
    resource_type: str
    resource_id: str
    region: str
    first_detected: datetime
    last_detected: datetime
    last_scan_id: uuid.UUID | None


class FindingDetail(FindingSummary):
    evidence: dict[str, Any]
    status_note: str | None
    status_updated_at: datetime | None
    status_updated_by_id: uuid.UUID | None  # None with a status_updated_at: changed by a scan
    resolved_at: datetime | None
    first_scan_id: uuid.UUID | None
    resource_name: str | None = None
    rule: RulePublic | None = None  # None only if the rule was removed from the catalog


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    note: str | None = Field(default=None, max_length=500)

    @field_validator("note")
    @classmethod
    def _strip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @model_validator(mode="after")
    def _false_positive_needs_a_reason(self) -> Self:
        if self.status == FindingStatus.FALSE_POSITIVE and not self.note:
            raise ValueError("A note explaining why is required for FALSE_POSITIVE")
        return self
