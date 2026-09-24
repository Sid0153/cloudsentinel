"""Dashboard summary and the X-Total-Count header of the list endpoints."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.aws_account import AwsAccount
from app.models.finding import Finding, FindingStatus
from app.models.user import User
from tests.api.conftest import RunScan
from tests.helpers import bearer, make_aws_account


def _summary(client: TestClient, user: User, **params: Any) -> dict[str, Any]:
    response = client.get("/api/dashboard/summary", headers=bearer(user), params=params)
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    return result


def test_empty_dashboard_before_any_scan(db_client: TestClient, viewer: User) -> None:
    summary = _summary(db_client, viewer)
    assert summary["aws_account_count"] == 0
    assert summary["resource_count"] == 0
    assert summary["open_finding_count"] == 0
    assert summary["overall_risk"] is None
    assert summary["latest_scan"] is None
    assert summary["top_risks"] == []
    # Every category is present with 0, so the charts always have all their bars.
    assert summary["findings_by_severity"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    assert summary["findings_by_priority"] == {"P1": 0, "P2": 0, "P3": 0, "P4": 0}


@pytest.mark.usefixtures("seeded")
def test_dashboard_after_a_scan(
    db_client: TestClient, run_scan: RunScan, viewer: User, account: AwsAccount
) -> None:
    scan = run_scan()
    summary = _summary(db_client, viewer)

    assert summary["aws_account_count"] == 1
    assert summary["resource_count"] == scan.resource_count
    assert summary["resources_by_type"]["AWS::S3::Bucket"] == 3
    assert summary["open_finding_count"] == 7
    assert summary["findings_by_severity"] == {"CRITICAL": 0, "HIGH": 5, "MEDIUM": 2, "LOW": 0}
    assert summary["findings_by_category"] == {
        "NETWORK": 1,
        "DATA_PROTECTION": 3,
        "IDENTITY": 3,
        "LOGGING": 0,
    }
    assert summary["findings_by_priority"] == {"P1": 4, "P2": 1, "P3": 0, "P4": 2}
    assert summary["overall_risk"]["score"] == 85
    assert summary["overall_risk"]["priority"] == "P1"
    assert summary["latest_scan"]["id"] == str(scan.id)
    assert [f["risk_score"] for f in summary["top_risks"]] == [85, 85, 85, 80, 75]

    other = _summary(db_client, viewer, aws_account_id=str(uuid.uuid4()))
    assert other["open_finding_count"] == 0 and other["latest_scan"] is None


@pytest.mark.usefixtures("seeded")
def test_closed_findings_leave_the_open_counts(
    db_client: TestClient, db_session: Session, run_scan: RunScan, viewer: User
) -> None:
    run_scan()
    for finding in db_session.scalars(select(Finding).where(Finding.rule_id == "CS-S3-002")):
        finding.status = FindingStatus.FALSE_POSITIVE
    db_session.commit()

    summary = _summary(db_client, viewer)
    assert summary["open_finding_count"] == 5
    assert summary["findings_by_severity"]["MEDIUM"] == 0
    assert summary["findings_by_status"] == {
        "OPEN": 5,
        "ACKNOWLEDGED": 0,
        "RESOLVED": 0,
        "FALSE_POSITIVE": 2,
    }


@pytest.mark.usefixtures("seeded")
def test_list_endpoints_report_the_total_for_pagination(
    db_client: TestClient, db_session: Session, run_scan: RunScan, viewer: User
) -> None:
    scan = run_scan()
    findings = db_client.get("/api/findings", headers=bearer(viewer), params={"limit": 2})
    assert len(findings.json()) == 2
    assert findings.headers["X-Total-Count"] == "7"
    high = db_client.get("/api/findings", headers=bearer(viewer), params={"severity": "HIGH"})
    assert high.headers["X-Total-Count"] == "5"

    resources = db_client.get("/api/resources", headers=bearer(viewer), params={"limit": 1})
    assert resources.headers["X-Total-Count"] == str(scan.resource_count)
    scans = db_client.get("/api/scans", headers=bearer(viewer))
    assert scans.headers["X-Total-Count"] == "1"

    # A second account without scans gets its own, empty, count.
    other = make_aws_account(db_session, account_id="111122223333")
    empty = db_client.get(
        "/api/scans", headers=bearer(viewer), params={"aws_account_id": str(other.id)}
    )
    assert empty.headers["X-Total-Count"] == "0"


@pytest.mark.usefixtures("seeded")
def test_findings_can_be_filtered_by_resource(
    db_client: TestClient, db_session: Session, run_scan: RunScan, viewer: User
) -> None:
    run_scan()
    bucket = db_session.scalar(
        select(Finding.resource_uuid).where(Finding.resource_id == "cs-public-bucket")
    )
    response = db_client.get(
        "/api/findings", headers=bearer(viewer), params={"resource_uuid": str(bucket)}
    )
    assert sorted(f["rule_id"] for f in response.json()) == ["CS-S3-001", "CS-S3-002"]
