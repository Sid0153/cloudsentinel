"""Turns a scan's rule evaluation into finding rows.

For every finding the scan either:
- detected again: update it (and reopen it if it had been marked RESOLVED);
- confirmed fixed: the rule evaluated the resource and it passed, so close it (RESOLVED);
- confirmed gone: the resource's service was read completely, in scope, and the resource was
  not there any more, so close it (RESOLVED);
- could not decide (UNKNOWN outcome, failed service, region not scanned): leave it untouched.
"Could not check" must never close a finding.
"""

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.coverage import SERVICE_FOR_TYPE, Coverage, type_fully_read
from app.domain.resources import ResourceKey, ResourceType, resource_key
from app.findings.fingerprint import fingerprint
from app.models.finding import ACTIVE_FINDING_STATUSES, Finding, FindingStatus
from app.models.resource import Resource
from app.risk.scoring import assess
from app.rules.engine import Detection, Evaluation

# Services whose resources live in one region; for the others (S3 listing, IAM) every
# resource is in scope no matter which regions the account registered.
REGIONAL_SERVICES = {"ec2", "cloudtrail"}


@dataclass(frozen=True)
class SyncResult:
    finding_counts: dict[str, int]  # this scan's detections per severity
    risk_scores: list[int]  # this scan's detections, without analyst-marked false positives


@dataclass(frozen=True)
class ScanScope:
    aws_account_uuid: uuid.UUID  # the AwsAccount row ID
    aws_account_id: str  # the 12-digit AWS account ID
    scan_id: uuid.UUID
    regions: list[str]
    coverage: Coverage
    now: datetime


def _in_scope(finding: Finding, scope: ScanScope) -> bool:
    try:
        resource_type = ResourceType(finding.resource_type)
    except ValueError:
        return False
    service = SERVICE_FOR_TYPE.get(resource_type)
    if service is None or not type_fully_read(scope.coverage, resource_type):
        return False
    return service not in REGIONAL_SERVICES or finding.region in scope.regions


def _set_status(finding: Finding, status: FindingStatus, note: str, now: datetime) -> None:
    finding.status = status
    finding.status_note = note
    finding.status_updated_at = now
    finding.status_updated_by_id = None  # changed by a scan, not a person
    finding.resolved_at = now if status == FindingStatus.RESOLVED else None


def _record_detection(
    detection: Detection, finding: Finding | None, fp: str, row: Resource, scope: ScanScope
) -> Finding:
    if finding is None:
        finding = Finding(
            aws_account_id=scope.aws_account_uuid,
            fingerprint=fp,
            status=FindingStatus.OPEN,
            first_detected=scope.now,
            first_scan_id=scope.scan_id,
        )
    elif finding.status == FindingStatus.RESOLVED:
        _set_status(finding, FindingStatus.OPEN, "Detected again by a later scan", scope.now)
    # ACKNOWLEDGED and FALSE_POSITIVE are analyst decisions and are kept.

    metadata = detection.rule.metadata
    finding.resource_uuid = row.id
    finding.rule_id = metadata.id
    finding.title = metadata.title
    finding.category = str(metadata.category)
    finding.severity = str(detection.severity)
    finding.evidence = detection.evidence
    risk = assess(
        metadata.id, str(detection.resource.resource_type), detection.severity, detection.evidence
    )
    finding.risk_score = risk.score
    finding.risk_breakdown = risk.breakdown
    finding.resource_type = str(detection.resource.resource_type)
    finding.resource_id = detection.resource.resource_id
    finding.region = detection.resource.region
    finding.last_detected = scope.now
    finding.last_scan_id = scope.scan_id
    return finding


def sync_findings(
    db: Session,
    scope: ScanScope,
    evaluation: Evaluation,
    rows: dict[ResourceKey, Resource],
) -> SyncResult:
    """Creates, updates and closes findings, and summarizes this scan's detections."""
    existing = {
        finding.fingerprint: finding
        for finding in db.scalars(
            select(Finding).where(Finding.aws_account_id == scope.aws_account_uuid)
        )
    }

    detected: set[str] = set()
    risk_scores: list[int] = []
    for detection in evaluation.detections:
        key = resource_key(detection.resource)
        fp = fingerprint(scope.aws_account_id, detection.rule.id, key)
        finding = _record_detection(detection, existing.get(fp), fp, rows[key], scope)
        if fp not in existing:
            db.add(finding)
            existing[fp] = finding
        detected.add(fp)
        if finding.status != FindingStatus.FALSE_POSITIVE and finding.risk_score is not None:
            risk_scores.append(finding.risk_score)

    for fp, finding in existing.items():
        if fp in detected or finding.status not in ACTIVE_FINDING_STATUSES:
            continue
        if finding.rule_id not in evaluation.rule_results:
            continue  # the rule was not run (for example it was removed from the catalog)
        key = (finding.region, finding.resource_type, finding.resource_id)
        if (finding.rule_id, key) in evaluation.passed:
            _set_status(
                finding, FindingStatus.RESOLVED, "A later scan found this fixed", scope.now
            )
        elif key not in rows and _in_scope(finding, scope):
            _set_status(
                finding,
                FindingStatus.RESOLVED,
                "The resource was no longer found by a complete scan",
                scope.now,
            )

    counts = dict(Counter(str(d.severity) for d in evaluation.detections))
    return SyncResult(finding_counts=counts, risk_scores=risk_scores)
