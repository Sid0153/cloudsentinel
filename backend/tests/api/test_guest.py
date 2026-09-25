"""Guest access for public demos: sign in without a password as a shared, non-admin account."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.rate_limit import SlidingWindowRateLimiter
from app.models.audit_log import AuditLog
from app.models.user import Role, User
from tests.helpers import TEST_PASSWORD, bearer, cookie_header, make_user, refresh_cookie_value

GUEST_EMAIL = "guest@demo.test"


@pytest.fixture
def guest_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("GUEST_EMAIL", GUEST_EMAIL)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def guest_client(guest_mode: None, db_client: TestClient) -> TestClient:
    return db_client


def _guest(db: Session, role: Role = Role.ANALYST, **values: object) -> User:
    user = make_user(db, role, email=GUEST_EMAIL)
    for name, value in values.items():
        setattr(user, name, value)
    db.commit()
    return user


def _events(db: Session, action: str) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


def test_guest_access_is_off_by_default(db_client: TestClient) -> None:
    assert db_client.post("/api/auth/guest").status_code == 404


def test_guest_sign_in_starts_a_normal_session(
    guest_client: TestClient, db_session: Session
) -> None:
    guest = _guest(db_session)
    response = guest_client.post("/api/auth/guest")
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == GUEST_EMAIL and body["user"]["role"] == "ANALYST"
    me = guest_client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.json()["id"] == str(guest.id)
    refresh_cookie_value(response)  # a refresh cookie was set, like a password login

    [event] = _events(db_session, "LOGIN_SUCCEEDED")
    assert event.actor_id == guest.id and event.details == {"method": "guest"}


@pytest.mark.parametrize(
    ("role", "values", "reason"),
    [
        (Role.ADMIN, {}, "guest_is_admin"),
        (Role.ANALYST, {"is_active": False}, "guest_disabled"),
    ],
)
def test_an_unusable_guest_account_is_refused(
    guest_client: TestClient,
    db_session: Session,
    role: Role,
    values: dict[str, object],
    reason: str,
) -> None:
    _guest(db_session, role, **values)
    response = guest_client.post("/api/auth/guest")
    assert response.status_code == 403
    assert "access_token" not in response.json()
    [event] = _events(db_session, "LOGIN_FAILED")
    assert event.details == {"reason": reason}


def test_a_missing_guest_account_is_refused(guest_client: TestClient, db_session: Session) -> None:
    assert guest_client.post("/api/auth/guest").status_code == 403
    [event] = _events(db_session, "LOGIN_FAILED")
    assert event.details == {"reason": "guest_missing"}


def test_lockout_does_not_block_the_guest(guest_client: TestClient, db_session: Session) -> None:
    # Someone guessing passwords for the guest email locks password sign-in, not guest access.
    _guest(db_session, locked_until=datetime.now(UTC) + timedelta(minutes=15))
    assert guest_client.post("/api/auth/guest").status_code == 200


def test_guest_sign_in_is_rate_limited(
    app: FastAPI, guest_client: TestClient, db_session: Session
) -> None:
    _guest(db_session)
    app.state.login_limiter = SlidingWindowRateLimiter(1)
    assert guest_client.post("/api/auth/guest").status_code == 200
    assert guest_client.post("/api/auth/guest").status_code == 429


def test_the_guest_password_cannot_be_changed(
    guest_client: TestClient, db_session: Session
) -> None:
    guest = _guest(db_session)
    response = guest_client.post(
        "/api/auth/change-password",
        headers=bearer(guest),
        json={"current_password": TEST_PASSWORD, "new_password": "another-long-password-1"},
    )
    assert response.status_code == 403


def test_other_users_can_still_change_their_password(
    guest_client: TestClient, db_session: Session
) -> None:
    _guest(db_session)
    user = make_user(db_session, password=TEST_PASSWORD)
    response = guest_client.post(
        "/api/auth/change-password",
        headers=bearer(user),
        json={"current_password": TEST_PASSWORD, "new_password": "another-long-password-1"},
    )
    assert response.status_code == 204


def test_a_replayed_guest_token_does_not_sign_out_other_visitors(
    guest_client: TestClient, db_session: Session
) -> None:
    _guest(db_session)
    first = refresh_cookie_value(guest_client.post("/api/auth/guest"))
    other_visitor = refresh_cookie_value(guest_client.post("/api/auth/guest"))
    guest_client.post("/api/auth/refresh", headers=cookie_header(first))
    replay = guest_client.post("/api/auth/refresh", headers=cookie_header(first))
    assert replay.status_code == 401

    [event] = _events(db_session, "REFRESH_TOKEN_REUSED")
    assert event.details == {"sessions_revoked": False}
    still_valid = guest_client.post("/api/auth/refresh", headers=cookie_header(other_visitor))
    assert still_valid.status_code == 200
