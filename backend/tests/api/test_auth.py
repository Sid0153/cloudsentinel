from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.tokens import ALGORITHM, ISSUER, hash_refresh_token
from app.core.config import get_settings
from app.models.refresh_token import RefreshToken
from app.models.user import Role
from tests.helpers import (
    TEST_PASSWORD,
    access_token_for,
    bearer,
    cookie_header,
    login,
    make_user,
    refresh_cookie_value,
)

NEW_PASSWORD = "a-brand-new-passphrase"


# ---------- login ----------


def test_login_success_returns_token_user_and_secure_cookie(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, Role.ANALYST, password=TEST_PASSWORD)
    response = login(db_client, user.email, TEST_PASSWORD)

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["user"]["email"] == user.email
    assert body["user"]["role"] == "ANALYST"
    assert "password" not in response.text

    cookie = response.headers["set-cookie"].lower()
    assert "cs_refresh=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/api/auth" in cookie


def test_refresh_token_is_stored_only_as_a_hash(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    plain = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    row = db_session.scalar(select(RefreshToken))
    assert row is not None
    assert row.token_hash == hash_refresh_token(plain)
    assert row.token_hash != plain


def test_login_email_is_case_insensitive(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, email="mixed@example.com", password=TEST_PASSWORD)
    assert login(db_client, "  Mixed@Example.COM ", TEST_PASSWORD).status_code == 200
    assert user.email == "mixed@example.com"


def test_wrong_password_and_unknown_email_look_identical(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    wrong_password = login(db_client, user.email, "definitely-the-wrong-one")
    unknown_email = login(db_client, "nobody@example.com", "definitely-the-wrong-one")

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()
    assert "set-cookie" not in wrong_password.headers


def test_account_locks_after_repeated_failures_then_recovers(
    db_client: TestClient, db_session: Session
) -> None:
    settings = get_settings()
    user = make_user(db_session, password=TEST_PASSWORD)
    for _ in range(settings.max_failed_logins):
        assert login(db_client, user.email, "wrong-password-here").status_code == 401

    # Even the correct password is refused while the account is locked.
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 401
    assert user.locked_until is not None

    user.locked_until = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 200


def test_successful_login_resets_failure_counter(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    login(db_client, user.email, "wrong-password-here")
    assert user.failed_login_count == 1
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 200
    assert user.failed_login_count == 0


def test_disabled_user_cannot_log_in(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD, is_active=False)
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 401


def test_login_is_rate_limited_per_client(db_client: TestClient) -> None:
    limit = get_settings().login_rate_limit_per_minute
    for _ in range(limit):
        assert login(db_client, "nobody@example.com", "irrelevant-password").status_code == 401
    blocked = login(db_client, "nobody@example.com", "irrelevant-password")
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "60"


def test_validation_error_does_not_echo_the_submitted_password(
    db_client: TestClient,
) -> None:
    secret = "x" * 200  # longer than the maximum allowed, so validation fails
    response = db_client.post("/api/auth/login", json={"email": "a@b.co", "password": secret})
    assert response.status_code == 422
    assert secret not in response.text


# ---------- access tokens on protected routes ----------


def test_me_requires_a_token(db_client: TestClient) -> None:
    assert db_client.get("/api/auth/me").status_code == 401


def test_me_returns_the_current_user(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, Role.VIEWER)
    response = db_client.get("/api/auth/me", headers=bearer(user))
    assert response.status_code == 200
    assert response.json()["email"] == user.email


def test_garbage_and_wrongly_signed_tokens_are_rejected(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session)
    forged = jwt.encode(
        {
            "sub": str(user.id),
            "iss": ISSUER,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "typ": "access",
        },
        "attacker-controlled-key-0123456789-abcdefghij",
        algorithm=ALGORITHM,
    )
    for token in ["garbage", forged]:
        response = db_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401


def test_expired_token_is_rejected(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session)
    expired = access_token_for(user, expires_in=timedelta(minutes=-1))
    response = db_client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_token_stops_working_when_the_user_is_disabled(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session)
    headers = bearer(user)
    assert db_client.get("/api/auth/me", headers=headers).status_code == 200
    user.is_active = False
    db_session.commit()
    assert db_client.get("/api/auth/me", headers=headers).status_code == 401


# ---------- refresh rotation ----------


def test_refresh_rotates_the_token_and_issues_a_working_access_token(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    first = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    response = db_client.post("/api/auth/refresh", headers=cookie_header(first))
    assert response.status_code == 200
    second = refresh_cookie_value(response)
    assert second != first

    me = db_client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {response.json()['access_token']}"}
    )
    assert me.status_code == 200


def test_replaying_an_old_refresh_token_revokes_the_whole_session(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    first = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    second = refresh_cookie_value(
        db_client.post("/api/auth/refresh", headers=cookie_header(first))
    )

    replay = db_client.post("/api/auth/refresh", headers=cookie_header(first))
    assert replay.status_code == 401

    # The replay is treated as theft: the newest token was revoked too.
    latest = db_client.post("/api/auth/refresh", headers=cookie_header(second))
    assert latest.status_code == 401


def test_refresh_without_or_with_bad_cookie_is_rejected(db_client: TestClient) -> None:
    db_client.cookies.clear()
    assert db_client.post("/api/auth/refresh").status_code == 401
    bad = db_client.post("/api/auth/refresh", headers=cookie_header("not-a-real-token"))
    assert bad.status_code == 401


def test_expired_refresh_token_is_rejected(db_client: TestClient, db_session: Session) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    cookie = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    row = db_session.scalar(select(RefreshToken))
    assert row is not None
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    assert db_client.post("/api/auth/refresh", headers=cookie_header(cookie)).status_code == 401


def test_refresh_is_refused_for_a_disabled_user(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    cookie = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))
    user.is_active = False
    db_session.commit()

    assert db_client.post("/api/auth/refresh", headers=cookie_header(cookie)).status_code == 401


# ---------- logout ----------


def test_logout_revokes_the_refresh_token_and_clears_the_cookie(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    cookie = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    response = db_client.post("/api/auth/logout", headers=cookie_header(cookie))
    assert response.status_code == 204
    assert "max-age=0" in response.headers["set-cookie"].lower()

    assert db_client.post("/api/auth/refresh", headers=cookie_header(cookie)).status_code == 401


def test_logout_without_a_session_still_succeeds(db_client: TestClient) -> None:
    db_client.cookies.clear()
    assert db_client.post("/api/auth/logout").status_code == 204


# ---------- change password ----------


def test_change_password_requires_the_current_password(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    response = db_client.post(
        "/api/auth/change-password",
        headers=bearer(user),
        json={"current_password": "not-my-password", "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 400
    assert login(db_client, user.email, TEST_PASSWORD).status_code == 200


def test_change_password_switches_password_and_ends_other_sessions(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    old_cookie = refresh_cookie_value(login(db_client, user.email, TEST_PASSWORD))

    response = db_client.post(
        "/api/auth/change-password",
        headers=bearer(user),
        json={"current_password": TEST_PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 204

    assert login(db_client, user.email, TEST_PASSWORD).status_code == 401
    assert login(db_client, user.email, NEW_PASSWORD).status_code == 200
    stale = db_client.post("/api/auth/refresh", headers=cookie_header(old_cookie))
    assert stale.status_code == 401


def test_change_password_rejects_a_weak_new_password_without_echoing_it(
    db_client: TestClient, db_session: Session
) -> None:
    user = make_user(db_session, password=TEST_PASSWORD)
    response = db_client.post(
        "/api/auth/change-password",
        headers=bearer(user),
        json={"current_password": TEST_PASSWORD, "new_password": "weak-pw"},
    )
    assert response.status_code == 422
    assert "weak-pw" not in response.text
