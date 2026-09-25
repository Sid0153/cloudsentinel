"""End-to-end scans: API request -> background job -> moto AWS -> PostgreSQL -> API response."""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.aws.collectors import iam as iam_collector
from app.aws.common import Boto3Session
from app.aws.session import SessionBuilder, build_session
from app.core.rate_limit import SlidingWindowRateLimiter
from app.models.audit_log import AuditLog
from app.models.resource import Resource
from app.models.scan import Scan, ScanStatus
from app.models.user import Role, User
from app.scans import discovery as discovery_module
from app.scans import service as scan_service
from app.scans.deps import get_scan_runner
from app.scans.service import INTERNAL_ERROR_MESSAGE, execute_scan, reconcile_stale_scans
from tests.aws.seed import seed_environment
from tests.helpers import MOTO_ACCOUNT_ID, bearer, make_aws_account, make_user

UseBuilder = Callable[[SessionBuilder], None]


@pytest.fixture
def use_builder(app: FastAPI, db_session: Session) -> UseBuilder:
    """Runs scans synchronously in the test's database session with the given AWS builder."""

    def configure(builder: SessionBuilder) -> None:
        def runner(scan_id: uuid.UUID) -> None:
            execute_scan(db_session, scan_id, builder)

        app.dependency_overrides[get_scan_runner] = lambda: runner

    configure(build_session)
    return configure


@pytest.fixture
def analyst(db_session: Session) -> User:
    return make_user(db_session, Role.ANALYST)


def _start(client: TestClient, user: User, account_id: uuid.UUID) -> dict[str, Any]:
    """Starts a scan (which the test runner executes before returning) and fetches it."""
    response = client.post(
        "/api/scans", headers=bearer(user), json={"aws_account_id": str(account_id)}
    )
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "PENDING"
    scan: dict[str, Any] = client.get(
        f"/api/scans/{response.json()['id']}", headers=bearer(user)
    ).json()
    return scan


@pytest.mark.usefixtures("mocked_aws", "use_builder")
def test_full_scan_discovers_and_stores_resources(
    db_client: TestClient,
    db_session: Session,
    analyst: User,
    policy_status: dict[str, bool],
) -> None:
    seeded = seed_environment()
    account = make_aws_account(db_session)

    scan = _start(db_client, analyst, account.id)
    assert scan["status"] == "COMPLETED", scan["coverage"]
    assert scan["caller_arn"]
    coverage = scan["coverage"]
    assert isinstance(coverage, dict)
    assert set(coverage) == {"ec2", "s3", "iam", "cloudtrail"}
    assert all(entry["status"] == "SUCCEEDED" for entry in coverage.values())

    counts = scan["resource_counts"]
    assert isinstance(counts, dict)
    assert counts["AWS::Account"] == 1
    assert counts["AWS::S3::Bucket"] == 3
    assert counts["AWS::CloudTrail::Trail"] == 1
    assert scan["resource_count"] == sum(counts.values())

    listing = db_client.get(
        "/api/resources",
        headers=bearer(analyst),
        params={"resource_type": "AWS::EC2::SecurityGroup", "region": "us-east-1"},
    )
    assert listing.status_code == 200
    group = next(r for r in listing.json() if r["resource_id"] == seeded.open_group_id)
    assert "config" not in group  # the list is a summary

    detail = db_client.get(f"/api/resources/{group['id']}", headers=bearer(analyst)).json()
    assert seeded.instance_id in detail["config"]["attached_instance_ids"]


@pytest.mark.usefixtures("mocked_aws", "use_builder", "policy_status")
def test_rescan_updates_resources_instead_of_duplicating_them(
    db_client: TestClient, db_session: Session, analyst: User
) -> None:
    seed_environment()
    account = make_aws_account(db_session)

    first = _start(db_client, analyst, account.id)
    count_after_first = db_session.scalar(select(func.count()).select_from(Resource))
    second = _start(db_client, analyst, account.id)
    count_after_second = db_session.scalar(select(func.count()).select_from(Resource))

    assert first["status"] == second["status"] == "COMPLETED"
    assert count_after_first == count_after_second == first["resource_count"]
    rows = db_session.scalars(select(Resource)).all()
    assert all(str(row.last_scan_id) == second["id"] for row in rows)
    assert all(row.first_seen <= row.last_seen for row in rows)

    history = db_client.get(
        "/api/scans", headers=bearer(analyst), params={"aws_account_id": str(account.id)}
    )
    assert [s["id"] for s in history.json()] == [second["id"], first["id"]]


@pytest.mark.usefixtures("mocked_aws", "use_builder", "policy_status")
def test_scan_refuses_credentials_for_a_different_account(
    db_client: TestClient, db_session: Session, analyst: User
) -> None:
    account = make_aws_account(db_session, account_id="111122223333")
    scan = _start(db_client, analyst, account.id)
    assert scan["status"] == "FAILED"
    assert scan["error_summary"] == (
        f"The AWS credentials belong to account {MOTO_ACCOUNT_ID}, not 111122223333. "
        "Nothing was scanned."
    )
    assert db_session.scalar(select(func.count()).select_from(Resource)) == 0


def test_missing_credentials_fail_the_scan_with_a_safe_message(
    db_client: TestClient, db_session: Session, analyst: User, use_builder: UseBuilder
) -> None:
    def no_credentials(role_arn: str | None, region: str) -> Boto3Session:
        raise NoCredentialsError()

    use_builder(no_credentials)
    scan = _start(db_client, analyst, make_aws_account(db_session).id)
    assert scan["status"] == "FAILED"
    assert scan["error_summary"] == "Could not authenticate to AWS: NoCredentialsError (Connect)"


@pytest.mark.usefixtures("mocked_aws", "use_builder", "policy_status")
def test_access_denied_on_one_api_is_partial_coverage_not_a_clean_result(
    db_client: TestClient,
    db_session: Session,
    analyst: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_environment()

    def denied(iam: object) -> None:
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "User arn:aws:iam::123456789012:user/scanner is not authorized",
                }
            },
            "GetAccountAuthorizationDetails",
        )

    monkeypatch.setattr(iam_collector, "read_authorization_details", denied)
    scan = _start(db_client, analyst, make_aws_account(db_session).id)

    assert scan["status"] == "COMPLETED_WITH_ERRORS"
    coverage = scan["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["iam"]["status"] == "PARTIAL"  # users still came from the credential report
    assert coverage["iam"]["errors"] == ["AccessDenied (GetAccountAuthorizationDetails)"]
    assert "scanner" not in str(scan)  # AWS's message (with an ARN) is not stored
    assert coverage["ec2"]["status"] == "SUCCEEDED"


@pytest.mark.usefixtures("mocked_aws", "use_builder", "policy_status")
def test_a_bug_in_one_service_does_not_lose_the_others(
    db_client: TestClient,
    db_session: Session,
    analyst: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(raw: object) -> None:
        raise ValueError("unexpected response shape")

    monkeypatch.setattr(discovery_module, "normalize_cloudtrail", broken)
    scan = _start(db_client, analyst, make_aws_account(db_session).id)

    assert scan["status"] == "COMPLETED_WITH_ERRORS"
    coverage = scan["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["cloudtrail"]["status"] == "FAILED"
    assert coverage["s3"]["status"] == "SUCCEEDED"
    assert "unexpected response shape" not in str(scan)


@pytest.mark.usefixtures("mocked_aws", "use_builder", "policy_status")
def test_unexpected_error_fails_the_scan_without_leaking_details(
    db_client: TestClient,
    db_session: Session,
    analyst: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*args: object) -> None:
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr(scan_service, "discover", explode)
    scan = _start(db_client, analyst, make_aws_account(db_session).id)
    assert scan["status"] == "FAILED"
    assert scan["error_summary"] == INTERNAL_ERROR_MESSAGE
    assert "must not leak" not in str(scan)


@pytest.mark.usefixtures("use_builder")
def test_only_one_active_scan_per_account(
    db_client: TestClient, db_session: Session, analyst: User
) -> None:
    account = make_aws_account(db_session)
    db_session.add(Scan(aws_account_id=account.id, status=ScanStatus.RUNNING))
    db_session.commit()
    response = db_client.post(
        "/api/scans", headers=bearer(analyst), json={"aws_account_id": str(account.id)}
    )
    assert response.status_code == 409


@pytest.mark.usefixtures("use_builder")
def test_unknown_account_and_unknown_scan_return_404(
    db_client: TestClient, analyst: User
) -> None:
    response = db_client.post(
        "/api/scans", headers=bearer(analyst), json={"aws_account_id": str(uuid.uuid4())}
    )
    assert response.status_code == 404
    assert db_client.get(f"/api/scans/{uuid.uuid4()}", headers=bearer(analyst)).status_code == 404
    missing = db_client.get(f"/api/resources/{uuid.uuid4()}", headers=bearer(analyst))
    assert missing.status_code == 404


def test_resource_filters_are_validated(db_client: TestClient, analyst: User) -> None:
    bad_type = db_client.get(
        "/api/resources", headers=bearer(analyst), params={"resource_type": "AWS::Nope"}
    )
    assert bad_type.status_code == 422
    too_many = db_client.get("/api/resources", headers=bearer(analyst), params={"limit": 1000})
    assert too_many.status_code == 422


def test_restart_marks_unfinished_scans_as_failed(db_session: Session) -> None:
    account = make_aws_account(db_session)
    statuses = [ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.COMPLETED]
    scans = [Scan(aws_account_id=account.id, status=status) for status in statuses]
    db_session.add_all(scans)
    db_session.commit()

    assert reconcile_stale_scans(db_session) == 2
    db_session.expire_all()
    assert [s.status for s in scans] == [ScanStatus.FAILED, ScanStatus.FAILED, ScanStatus.COMPLETED]
    assert scans[0].error_summary is not None and "restarted" in scans[0].error_summary


@pytest.mark.usefixtures("use_builder")
def test_starting_scans_is_rate_limited_per_client(
    app: FastAPI, db_client: TestClient, db_session: Session, analyst: User
) -> None:
    app.state.scan_limiter = SlidingWindowRateLimiter(1)
    body = {"aws_account_id": str(uuid.uuid4())}
    first = db_client.post("/api/scans", headers=bearer(analyst), json=body)
    second = db_client.post("/api/scans", headers=bearer(analyst), json=body)
    assert first.status_code == 404  # counted even though the account does not exist
    assert second.status_code == 429
    [event] = db_session.scalars(select(AuditLog).where(AuditLog.action == "RATE_LIMITED"))
    assert event.details == {"limit": "scan"} and event.actor_id == analyst.id
