"""Authorization tests that fail loudly when a route is added without an access decision.

EXPECTED_ACCESS is the single source of truth for who may call what. Every API route must
appear either there or in PUBLIC_ROUTES, and every entry is exercised for every role.
"""

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.deps import AnalystUser
from app.models.user import Role, User
from tests.helpers import access_token_for, make_user

Route = tuple[str, str]  # (HTTP method, path)

PUBLIC_ROUTES: set[Route] = {
    ("GET", "/api/health/live"),
    ("GET", "/api/health/ready"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/refresh"),
    ("POST", "/api/auth/logout"),
}

# Minimum role required. None means "any signed-in user".
EXPECTED_ACCESS: dict[Route, Role | None] = {
    ("GET", "/api/auth/me"): None,
    ("POST", "/api/auth/change-password"): None,
    ("GET", "/api/users"): Role.ADMIN,
    ("POST", "/api/users"): Role.ADMIN,
    ("PATCH", "/api/users/{user_id}"): Role.ADMIN,
}

_RANK = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


def _allowed(role: Role, minimum: Role | None) -> bool:
    return minimum is None or _RANK[role] >= _RANK[minimum]


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def _api_routes(app: FastAPI) -> set[Route]:
    """Every (method, path) the app serves, read from its OpenAPI schema.

    Walking app.routes looks simpler, but what it contains depends on the FastAPI version
    (an earlier version of this test found no routes and silently checked nothing).
    """
    paths = app.openapi()["paths"]
    return {
        (method.upper(), path)
        for path, operations in paths.items()
        for method in operations
        if method.upper() in _HTTP_METHODS
    }


def test_every_route_has_a_declared_access_rule(app: FastAPI) -> None:
    routes = _api_routes(app)
    assert len(routes) >= len(PUBLIC_ROUTES) + len(EXPECTED_ACCESS)
    declared = PUBLIC_ROUTES | set(EXPECTED_ACCESS)
    assert routes - declared == set(), "route added without an access rule in this file"
    assert declared - routes == set(), "access rule refers to a route that no longer exists"


def _matrix() -> list[tuple[str, str, Role | None, Role]]:
    return [
        (method, path, minimum, role)
        for (method, path), minimum in EXPECTED_ACCESS.items()
        for role in Role
    ]


@pytest.fixture
def users_by_role(db_session: Session) -> dict[Role, User]:
    return {role: make_user(db_session, role) for role in Role}


@pytest.mark.parametrize(("method", "path"), sorted(EXPECTED_ACCESS))
def test_anonymous_requests_are_rejected(
    db_client: TestClient, method: str, path: str
) -> None:
    url = path.replace("{user_id}", str(uuid.uuid4()))
    response = db_client.request(method, url)
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path", "minimum", "role"), _matrix())
def test_role_matrix(
    db_client: TestClient,
    users_by_role: dict[Role, User],
    method: str,
    path: str,
    minimum: Role | None,
    role: Role,
) -> None:
    url = path.replace("{user_id}", str(uuid.uuid4()))
    headers = {"Authorization": f"Bearer {access_token_for(users_by_role[role])}"}
    # Requests carry no body. Authorization runs before validation, so a permitted role gets
    # a 422/404/200 (anything but 401/403) and a forbidden role is stopped with 403.
    response = db_client.request(method, url, headers=headers)
    if _allowed(role, minimum):
        assert response.status_code not in (401, 403)
    else:
        assert response.status_code == 403


def test_analyst_level_dependency_admits_analyst_and_admin_only(
    app: FastAPI, db_client: TestClient, db_session: Session
) -> None:
    """The ANALYST tier has no real endpoint yet; prove the dependency semantics directly."""

    def analyst_only(user: AnalystUser) -> dict[str, str]:
        return {"role": user.role}

    app.add_api_route("/api/_test/analyst-only", analyst_only)

    results: dict[Role, int] = {}
    for role in Role:
        user = make_user(db_session, role)
        response = db_client.get(
            "/api/_test/analyst-only",
            headers={"Authorization": f"Bearer {access_token_for(user)}"},
        )
        results[role] = response.status_code
    assert results == {Role.VIEWER: 403, Role.ANALYST: 200, Role.ADMIN: 200}
