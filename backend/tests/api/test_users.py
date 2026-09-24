import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import Role
from tests.helpers import TEST_PASSWORD, bearer, login, make_user

STRONG_PASSWORD = "a-perfectly-good-passphrase"


def test_admin_can_create_a_user_who_can_then_log_in(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    response = db_client.post(
        "/api/users",
        headers=bearer(admin),
        json={"email": "New.Person@Example.com", "password": STRONG_PASSWORD, "role": "ANALYST"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new.person@example.com"
    assert body["role"] == "ANALYST"
    assert "password" not in response.text
    assert "hash" not in response.text

    assert login(db_client, "new.person@example.com", STRONG_PASSWORD).status_code == 200


def test_duplicate_email_is_rejected_case_insensitively(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    make_user(db_session, email="taken@example.com")
    response = db_client.post(
        "/api/users",
        headers=bearer(admin),
        json={"email": "TAKEN@example.com", "password": STRONG_PASSWORD, "role": "VIEWER"},
    )
    assert response.status_code == 409


def test_invalid_input_is_rejected_without_echoing_the_password(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    headers = bearer(admin)

    weak = db_client.post(
        "/api/users",
        headers=headers,
        json={"email": "a@example.com", "password": "weak-pw", "role": "VIEWER"},
    )
    bad_email = db_client.post(
        "/api/users",
        headers=headers,
        json={"email": "not-an-email", "password": STRONG_PASSWORD, "role": "VIEWER"},
    )
    bad_role = db_client.post(
        "/api/users",
        headers=headers,
        json={"email": "b@example.com", "password": STRONG_PASSWORD, "role": "SUPERUSER"},
    )
    assert weak.status_code == bad_email.status_code == bad_role.status_code == 422
    assert "weak-pw" not in weak.text
    assert STRONG_PASSWORD not in bad_email.text


def test_list_users_returns_public_fields_only(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    make_user(db_session, Role.VIEWER)
    response = db_client.get("/api/users", headers=bearer(admin))
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 2
    assert set(users[0]) == {"id", "email", "role", "is_active", "created_at", "last_login_at"}


def test_list_users_validates_paging_parameters(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    assert db_client.get("/api/users?limit=0", headers=bearer(admin)).status_code == 422
    assert db_client.get("/api/users?limit=1000", headers=bearer(admin)).status_code == 422
    assert db_client.get("/api/users?offset=-1", headers=bearer(admin)).status_code == 422


def test_admin_can_change_a_role(db_client: TestClient, db_session: Session) -> None:
    admin = make_user(db_session, Role.ADMIN)
    target = make_user(db_session, Role.VIEWER)
    response = db_client.patch(
        f"/api/users/{target.id}", headers=bearer(admin), json={"role": "ANALYST"}
    )
    assert response.status_code == 200
    assert response.json()["role"] == "ANALYST"


def test_role_change_takes_effect_immediately(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    other_admin = make_user(db_session, Role.ADMIN)
    other_headers = bearer(other_admin)
    assert db_client.get("/api/users", headers=other_headers).status_code == 200

    demote = db_client.patch(
        f"/api/users/{other_admin.id}", headers=bearer(admin), json={"role": "VIEWER"}
    )
    assert demote.status_code == 200
    # Same token as before, but the role is read from the database on every request.
    assert db_client.get("/api/users", headers=other_headers).status_code == 403


def test_deactivating_a_user_ends_their_access_and_sessions(
    db_client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, Role.ADMIN)
    target = make_user(db_session, Role.VIEWER, password=TEST_PASSWORD)
    logged_in = login(db_client, target.email, TEST_PASSWORD)
    token_headers = {"Authorization": f"Bearer {logged_in.json()['access_token']}"}
    cookie = logged_in.cookies.get("cs_refresh")
    assert cookie

    deactivate = db_client.patch(
        f"/api/users/{target.id}", headers=bearer(admin), json={"is_active": False}
    )
    assert deactivate.status_code == 200

    assert db_client.get("/api/auth/me", headers=token_headers).status_code == 401
    refresh = db_client.post("/api/auth/refresh", headers={"Cookie": f"cs_refresh={cookie}"})
    assert refresh.status_code == 401
    assert login(db_client, target.email, TEST_PASSWORD).status_code == 401


def test_admin_cannot_modify_themselves(db_client: TestClient, db_session: Session) -> None:
    admin = make_user(db_session, Role.ADMIN)
    response = db_client.patch(
        f"/api/users/{admin.id}", headers=bearer(admin), json={"role": "VIEWER"}
    )
    assert response.status_code == 400


def test_patch_unknown_user_and_empty_body(db_client: TestClient, db_session: Session) -> None:
    admin = make_user(db_session, Role.ADMIN)
    missing = db_client.patch(
        f"/api/users/{uuid.uuid4()}", headers=bearer(admin), json={"role": "VIEWER"}
    )
    assert missing.status_code == 404
    empty = db_client.patch(f"/api/users/{uuid.uuid4()}", headers=bearer(admin), json={})
    assert empty.status_code == 422
