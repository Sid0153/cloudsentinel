"""Authorization tests that fail loudly when a route is added without an access decision.

EXPECTED_ACCESS is the single source of truth for who may call what. Every API route must
appear either there or in PUBLIC_ROUTES, and every entry is exercised for every role.
"""

import re
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

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
    ("GET", "/api/aws-accounts"): None,
    ("POST", "/api/aws-accounts"): Role.ADMIN,
    ("POST", "/api/aws-accounts/{aws_account_id}/verify"): Role.ADMIN,
    ("GET", "/api/scans"): None,
    ("POST", "/api/scans"): Role.ANALYST,
    ("GET", "/api/scans/{scan_id}"): None,
    ("GET", "/api/resources"): None,
    ("GET", "/api/resources/{resource_uuid}"): None,
    ("GET", "/api/findings"): None,
    ("GET", "/api/findings/{finding_id}"): None,
    ("PATCH", "/api/findings/{finding_id}"): Role.ANALYST,
    ("GET", "/api/rules"): None,
    ("GET", "/api/dashboard/summary"): None,
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


def _url(path: str) -> str:
    """Fills every path parameter with a random UUID (the target need not exist)."""
    return re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)


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
    response = db_client.request(method, _url(path))
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
    url = _url(path)
    headers = {"Authorization": f"Bearer {access_token_for(users_by_role[role])}"}
    # Requests carry no body. Authorization runs before validation, so a permitted role gets
    # a 422/404/200 (anything but 401/403) and a forbidden role is stopped with 403.
    response = db_client.request(method, url, headers=headers)
    if _allowed(role, minimum):
        assert response.status_code not in (401, 403)
    else:
        assert response.status_code == 403
