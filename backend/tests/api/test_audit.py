"""Audit logging: which actions are recorded, what is (and is never) stored, who can read it,
and that the table cannot be changed after the fact."""

import json
import uuid
from typing import Any

import pytest
from botocore.exceptions import NoCredentialsError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.aws.common import Boto3Session
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.user import Role, User
from app.scans.deps import get_aws_session_builder
from app.scans.service import reconcile_stale_scans
from tests.api.conftest import RunScan
from tests.helpers import (
    TEST_PASSWORD,
    bearer,
    cookie_header,
    login,
    make_aws_account,
    make_user,
    refresh_cookie_value,
)


def _events(db: Session, action: str | None = None) -> list[AuditLog]:
    statement = select(AuditLog).order_by(AuditLog.created_at, AuditLog.id)
    if action is not None:
        statement = statement.where(AuditLog.action == action)
    return list(db.scalars(statement))


def _as_text(entries: list[AuditLog]) -> str:
    """Everything stored in the rows, to check that no secret ended up anywhere."""
    return json.dumps(
        [{c.name: getattr(e, c.name) for c in AuditLog.__table__.columns} for e in entries],
        default=str,
    )


# --- Authentication ---------------------------------------------------------------------------


def test_successful_login_records_who_from_where_and_which_request(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    response = login(db_client, user.email, TEST_PASSWORD)
    assert response.status_code == 200

    [entry] = _events(db_session, "LOGIN_SUCCEEDED")
    assert entry.outcome == "SUCCESS"
    assert entry.actor_id == user.id and entry.actor_email == user.email
    assert entry.target_type == "USER" and entry.target_id == str(user.id)
    assert entry.ip_address == "testclient"  # the TestClient's client address
    assert entry.request_id == response.headers["X-Request-ID"]
    access_token = response.json()["access_token"]
    stored = _as_text(_events(db_session))
    assert TEST_PASSWORD not in stored and access_token not in stored


def test_failed_logins_record_the_reason_but_never_the_submitted_email_or_password(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    typed_email = "someone-who-does-not-exist@example.com"
    typed_password = "a-password-typed-by-mistake"
    assert login(db_client, typed_email, typed_password).status_code == 401
    assert login(db_client, user.email, typed_password).status_code == 401

    unknown, wrong = _events(db_session, "LOGIN_FAILED")
    assert unknown.details == {"reason": "unknown_email"}
    assert unknown.actor_id is None and unknown.target_id is None
    assert wrong.details == {"reason": "wrong_password"}
    assert wrong.target_id == str(user.id)
    stored = _as_text(_events(db_session))
    assert typed_email not in stored and typed_password not in stored


def test_lockout_is_recorded(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    for _ in range(5):  # max_failed_logins
        login(db_client, user.email, "wrong-password-123")
    [locked] = _events(db_session, "ACCOUNT_LOCKED")
    assert locked.target_id == str(user.id)
    assert locked.details == {"minutes": 15}

    login(db_client, user.email, TEST_PASSWORD)  # correct, but the account is locked
    assert _events(db_session, "LOGIN_FAILED")[-1].details == {"reason": "account_locked"}


def test_rate_limited_logins_are_recorded(db_client: TestClient, db_session: Session) -> None:
    for _ in range(11):  # login_rate_limit_per_minute is 10
        response = login(db_client, "x@example.com", "whatever-password")
    assert response.status_code == 429
    [limited] = _events(db_session, "LOGIN_RATE_LIMITED")
    assert limited.outcome == "FAILURE" and limited.ip_address == "testclient"


def test_logout_and_refresh_token_reuse_are_recorded(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    first = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    second = refresh_cookie_value(db_client.post("/api/auth/refresh", headers=cookie_header(first)))
    db_client.post("/api/auth/refresh", headers=cookie_header(first))  # replayed: theft?

    [reuse] = _events(db_session, "REFRESH_TOKEN_REUSED")
    assert reuse.target_id == str(user.id) and reuse.details == {"sessions_revoked": True}

    other = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    db_client.post("/api/auth/logout", headers=cookie_header(other))
    [logout] = _events(db_session, "LOGOUT")
    assert logout.actor_id == user.id
    stored = _as_text(_events(db_session))
    assert first not in stored and second not in stored and other not in stored


def test_password_changes_are_recorded_without_the_passwords(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)

    def change(current: str) -> int:
        body = {"current_password": current, "new_password": "a-brand-new-password"}
        response = db_client.post("/api/auth/change-password", headers=bearer(user), json=body)
        return int(response.status_code)

    assert change("not-the-password") == 400
    assert change(TEST_PASSWORD) == 204

    failed, changed = _events(db_session, "PASSWORD_CHANGED")
    assert failed.outcome == "FAILURE" and failed.details == {"reason": "wrong_current_password"}
    assert changed.outcome == "SUCCESS" and changed.actor_id == user.id
    stored = _as_text(_events(db_session))
    assert "a-brand-new-password" not in stored and "not-the-password" not in stored


# --- Authorization and administration ----------------------------------------------------------


def test_access_denied_is_recorded_with_the_route(
    db_client: TestClient, db_session: Session
) -> None:
    viewer = make_user(db_session, Role.VIEWER)
    assert db_client.get("/api/users", headers=bearer(viewer)).status_code == 403
    [denied] = _events(db_session, "ACCESS_DENIED")
    assert denied.actor_id == viewer.id
    assert denied.details == {"method": "GET", "path": "/api/users", "role": "VIEWER"}


def test_user_creation_and_role_changes_are_recorded(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    created = db_client.post(
        "/api/users",
        headers=bearer(admin),
        json={"email": "new@example.com", "password": "initial-password-1", "role": "VIEWER"},
    ).json()
    url = f"/api/users/{created['id']}"
    db_client.patch(url, headers=bearer(admin), json={"role": "ANALYST", "is_active": False})
    db_client.patch(url, headers=bearer(admin), json={"role": "ANALYST"})

    [creation] = _events(db_session, "USER_CREATED")
    assert creation.actor_id == admin.id and creation.target_id == created["id"]
    assert creation.details == {"email": "new@example.com", "role": "VIEWER", "via": "api"}
    [update] = _events(db_session, "USER_UPDATED")  # the second PATCH changed nothing
    assert update.details == {
        "email": "new@example.com",
        "role": {"from": "VIEWER", "to": "ANALYST"},
        "is_active": {"from": True, "to": False},
    }
    assert "initial-password-1" not in _as_text(_events(db_session))


@pytest.mark.usefixtures("mocked_aws")
def test_aws_account_registration_and_verification_are_recorded(
    app: FastAPI, db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    registered = db_client.post(
        "/api/aws-accounts",
        headers=bearer(admin),
        json={"account_id": "123456789012", "name": "Prod", "regions": ["us-east-1"]},
    ).json()
    db_client.post(f"/api/aws-accounts/{registered['id']}/verify", headers=bearer(admin))
    other = make_aws_account(db_session, account_id="111122223333")
    db_client.post(f"/api/aws-accounts/{other.id}/verify", headers=bearer(admin))

    def no_credentials(role_arn: str | None, region: str) -> Boto3Session:
        raise NoCredentialsError()

    app.dependency_overrides[get_aws_session_builder] = lambda: no_credentials
    db_client.post(f"/api/aws-accounts/{other.id}/verify", headers=bearer(admin))

    [registration] = _events(db_session, "AWS_ACCOUNT_REGISTERED")
    assert registration.details["account_id"] == "123456789012"
    ok, mismatch, failed = _events(db_session, "AWS_ACCOUNT_VERIFIED")
    assert ok.outcome == "SUCCESS" and ok.details["matches"] is True
    assert mismatch.outcome == "FAILURE" and mismatch.details["matches"] is False
    assert failed.outcome == "FAILURE" and failed.details == {"error": "NoCredentialsError"}


# --- Scans and findings ------------------------------------------------------------------------


@pytest.mark.usefixtures("seeded")
def test_scan_lifecycle_and_triage_are_recorded(
    db_client: TestClient, db_session: Session, run_scan: RunScan, analyst: User
) -> None:
    scan = run_scan()
    [started] = _events(db_session, "SCAN_STARTED")
    assert started.actor_id == analyst.id and started.target_id == str(scan.id)
    [completed] = _events(db_session, "SCAN_COMPLETED")
    assert completed.actor_id is None  # a system event
    assert completed.details["finding_count"] == 7 and completed.details["status"] == "COMPLETED"

    finding = db_session.scalars(select(Finding)).first()
    assert finding is not None
    note = "Accepted until the migration in Q4"
    db_client.patch(
        f"/api/findings/{finding.id}",
        headers=bearer(analyst),
        json={"status": "ACKNOWLEDGED", "note": note},
    )
    [triage] = _events(db_session, "FINDING_STATUS_CHANGED")
    assert triage.actor_id == analyst.id and triage.target_id == str(finding.id)
    assert triage.details["from"] == "OPEN" and triage.details["to"] == "ACKNOWLEDGED"
    assert triage.details["note_provided"] is True
    assert note not in _as_text([triage])  # the note stays on the finding only


def test_interrupted_scans_are_recorded_as_failed(db_session: Session) -> None:
    account = make_aws_account(db_session)
    scan = Scan(aws_account_id=account.id, status=ScanStatus.RUNNING)
    db_session.add(scan)
    db_session.commit()
    assert reconcile_stale_scans(db_session) == 1
    [failed] = _events(db_session, "SCAN_FAILED")
    assert failed.target_id == str(scan.id) and "restarted" in failed.details["error"]


# --- Reading the log ---------------------------------------------------------------------------


def test_admin_reads_newest_first_with_filters_and_a_total(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN, password=TEST_PASSWORD)
    viewer = make_user(db_session, Role.VIEWER)
    login(db_client, admin.email, "wrong-password-123")
    login(db_client, admin.email, TEST_PASSWORD)
    db_client.get("/api/users", headers=bearer(viewer))  # ACCESS_DENIED

    def read(**params: Any) -> tuple[list[dict[str, Any]], str]:
        response = db_client.get("/api/audit-logs", headers=bearer(admin), params=params)
        assert response.status_code == 200, response.text
        return response.json(), response.headers["X-Total-Count"]

    entries, total = read()
    assert [e["action"] for e in entries] == ["ACCESS_DENIED", "LOGIN_SUCCEEDED", "LOGIN_FAILED"]
    assert total == "3"
    failures, _ = read(outcome="FAILURE")
    assert {e["action"] for e in failures} == {"ACCESS_DENIED", "LOGIN_FAILED"}
    logins, count = read(action=["LOGIN_SUCCEEDED", "LOGIN_FAILED"], limit=1)
    assert len(logins) == 1 and count == "2"
    by_actor, _ = read(actor_id=str(viewer.id))
    assert [e["action"] for e in by_actor] == ["ACCESS_DENIED"]
    assert read(target_id=str(uuid.uuid4()))[1] == "0"


def test_non_admins_cannot_read_the_log_and_bad_filters_are_rejected(
    db_client: TestClient, db_session: Session
) -> None:
    analyst = make_user(db_session, Role.ANALYST)
    admin = make_user(db_session, Role.ADMIN)
    assert db_client.get("/api/audit-logs", headers=bearer(analyst)).status_code == 403
    for params in ({"action": "DELETE_EVERYTHING"}, {"outcome": "MAYBE"}, {"limit": 1000}):
        response = db_client.get("/api/audit-logs", headers=bearer(admin), params=params)
        assert response.status_code == 422
    assert db_client.get("/api/audit-logs").status_code == 401


# --- Tamper resistance -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_logs SET outcome = 'SUCCESS'",
        "DELETE FROM audit_logs",
        "TRUNCATE audit_logs",
    ],
)
def test_the_database_refuses_to_change_or_delete_audit_records(
    db_session: Session, statement: str
) -> None:
    viewer = make_user(db_session, Role.VIEWER)
    db_session.add(AuditLog(action="LOGIN_FAILED", outcome="FAILURE", actor_id=viewer.id))
    db_session.commit()

    savepoint = db_session.begin_nested()
    with pytest.raises(DBAPIError, match="append-only"):
        db_session.execute(text(statement))
    savepoint.rollback()
    assert len(_events(db_session)) == 1
