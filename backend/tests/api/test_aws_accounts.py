import pytest
from botocore.exceptions import NoCredentialsError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.aws.common import Boto3Session
from app.models.user import Role
from app.scans.deps import get_aws_session_builder
from tests.helpers import MOTO_ACCOUNT_ID, bearer, make_aws_account, make_user

VALID = {"account_id": MOTO_ACCOUNT_ID, "name": "Sandbox", "regions": ["us-east-1"]}


def test_admin_registers_an_account_without_any_credentials(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    payload = {
        **VALID,
        "name": "  Sandbox  ",
        "regions": ["US-EAST-1", "eu-west-1", "us-east-1"],
        "role_arn": f"arn:aws:iam::{MOTO_ACCOUNT_ID}:role/CloudSentinelReadOnly",
    }
    response = db_client.post("/api/aws-accounts", headers=bearer(admin), json=payload)
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Sandbox"
    assert body["regions"] == ["us-east-1", "eu-west-1"]
    assert set(body) == {"id", "account_id", "name", "regions", "role_arn", "created_at"}


def test_duplicate_account_is_rejected(db_client: TestClient, db_session: Session) -> None:
    admin = make_user(db_session, Role.ADMIN)
    make_aws_account(db_session)
    response = db_client.post("/api/aws-accounts", headers=bearer(admin), json=VALID)
    assert response.status_code == 409


@pytest.mark.parametrize(
    "override",
    [
        {"account_id": "12345"},
        {"account_id": "12345678901a"},
        {"regions": []},
        {"regions": ["mars-north-1a"]},
        {"regions": ["us-east-1; DROP TABLE users"]},
        {"name": "   "},
        {"role_arn": "arn:aws:iam::123456789012:user/not-a-role"},
    ],
)
def test_invalid_input_is_rejected(
    db_client: TestClient, db_session: Session, override: dict[str, object]
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    response = db_client.post(
        "/api/aws-accounts", headers=bearer(admin), json={**VALID, **override}
    )
    assert response.status_code == 422


def test_any_signed_in_user_can_list_accounts(
    db_client: TestClient, db_session: Session
) -> None:
    make_aws_account(db_session)
    viewer = make_user(db_session, Role.VIEWER)
    response = db_client.get("/api/aws-accounts", headers=bearer(viewer))
    assert response.status_code == 200
    assert [a["account_id"] for a in response.json()] == [MOTO_ACCOUNT_ID]


@pytest.mark.usefixtures("mocked_aws")
def test_verify_reports_whether_credentials_match(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    matching = make_aws_account(db_session)
    other = make_aws_account(db_session, account_id="111122223333")

    ok = db_client.post(f"/api/aws-accounts/{matching.id}/verify", headers=bearer(admin))
    assert ok.status_code == 200
    assert ok.json()["matches"] is True
    assert ok.json()["caller_account_id"] == MOTO_ACCOUNT_ID

    mismatch = db_client.post(f"/api/aws-accounts/{other.id}/verify", headers=bearer(admin))
    assert mismatch.status_code == 200
    assert mismatch.json()["matches"] is False


def test_verify_without_credentials_returns_a_safe_error(
    app: FastAPI, db_client: TestClient, db_session: Session
) -> None:
    def no_credentials(role_arn: str | None, region: str) -> Boto3Session:
        raise NoCredentialsError()

    app.dependency_overrides[get_aws_session_builder] = lambda: no_credentials
    admin = make_user(db_session, Role.ADMIN)
    account = make_aws_account(db_session)
    response = db_client.post(f"/api/aws-accounts/{account.id}/verify", headers=bearer(admin))
    assert response.status_code == 502
    assert response.json()["detail"] == "Could not verify AWS access: NoCredentialsError"
