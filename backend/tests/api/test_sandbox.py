"""Sandbox routes, with moto's in-process mock standing in for the simulator."""

from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.sandbox import get_sandbox_clients
from app.aws.sandbox import CONTROLS, SANDBOX_ACCOUNT_ID, SANDBOX_REGION, Clients, clients_for
from app.core.config import get_settings
from app.core.rate_limit import SlidingWindowRateLimiter
from app.models.audit_log import AuditLog
from app.models.user import Role, User
from tests.helpers import bearer, make_user

DEFAULTS = {control.key: control.insecure_by_default for control in CONTROLS}


@pytest.fixture
def analyst(db_session: Session) -> User:
    return make_user(db_session, Role.ANALYST)


@pytest.fixture
def sandbox(app: FastAPI, mocked_aws: None) -> None:
    """Sandbox routes use moto's mock instead of a simulator container."""
    clients = clients_for(boto3.Session(region_name=SANDBOX_REGION))
    app.dependency_overrides[get_sandbox_clients] = lambda: clients


def _states(body: dict[str, Any]) -> dict[str, bool]:
    return {control["key"]: control["insecure"] for control in body["controls"]}


def _events(db: Session, action: str) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


@pytest.mark.usefixtures("sandbox")
def test_viewers_see_the_environment_and_its_switches(
    db_client: TestClient, db_session: Session
) -> None:
    viewer = make_user(db_session, Role.VIEWER)
    response = db_client.get("/api/sandbox", headers=bearer(viewer))
    assert response.status_code == 200
    body = response.json()
    assert body["account_id"] == SANDBOX_ACCOUNT_ID and body["region"] == SANDBOX_REGION
    assert _states(body) == DEFAULTS
    first = body["controls"][0]
    assert set(first) == {
        "key",
        "title",
        "description",
        "rule_id",
        "insecure",
        "insecure_by_default",
    }


@pytest.mark.usefixtures("sandbox")
def test_analysts_can_flip_a_switch_and_it_is_audited(
    db_client: TestClient, db_session: Session, analyst: User
) -> None:
    response = db_client.patch(
        "/api/sandbox/controls/rdp-open", headers=bearer(analyst), json={"insecure": True}
    )
    assert response.status_code == 200
    assert response.json()["insecure"] is True and response.json()["rule_id"] == "CS-SG-002"
    states = _states(db_client.get("/api/sandbox", headers=bearer(analyst)).json())
    assert states == {**DEFAULTS, "rdp-open": True}

    [event] = _events(db_session, "SANDBOX_CHANGED")
    assert event.actor_id == analyst.id
    assert (event.target_type, event.target_id) == ("SANDBOX_CONTROL", "rdp-open")
    assert event.details == {"insecure": True, "rule_id": "CS-SG-002"}


@pytest.mark.usefixtures("sandbox")
def test_reset_restores_every_default_and_is_audited(
    db_client: TestClient, db_session: Session, analyst: User
) -> None:
    for control in CONTROLS:
        db_client.patch(
            f"/api/sandbox/controls/{control.key}",
            headers=bearer(analyst),
            json={"insecure": not control.insecure_by_default},
        )
    response = db_client.post("/api/sandbox/reset", headers=bearer(analyst))
    assert response.status_code == 200
    assert _states(response.json()) == DEFAULTS
    [event] = _events(db_session, "SANDBOX_RESET")
    assert event.actor_id == analyst.id


@pytest.mark.usefixtures("sandbox")
def test_unknown_switch_and_bad_body_are_rejected(db_client: TestClient, analyst: User) -> None:
    unknown = db_client.patch(
        "/api/sandbox/controls/nope", headers=bearer(analyst), json={"insecure": True}
    )
    assert unknown.status_code == 404
    invalid = db_client.patch(
        "/api/sandbox/controls/ssh-open", headers=bearer(analyst), json={"insecure": "maybe"}
    )
    assert invalid.status_code == 422


@pytest.mark.usefixtures("sandbox")
def test_sandbox_changes_are_rate_limited_per_client(
    app: FastAPI, db_client: TestClient, db_session: Session, analyst: User
) -> None:
    app.state.sandbox_limiter = SlidingWindowRateLimiter(1)
    body = {"insecure": True}
    first = db_client.patch("/api/sandbox/controls/rdp-open", headers=bearer(analyst), json=body)
    second = db_client.post("/api/sandbox/reset", headers=bearer(analyst))
    assert first.status_code == 200
    assert second.status_code == 429 and second.headers["Retry-After"] == "60"
    [event] = _events(db_session, "RATE_LIMITED")
    assert event.details == {"limit": "sandbox"} and event.outcome == "FAILURE"


class _Unreachable:
    """Every AWS call fails the way boto3 fails when the simulator is down."""

    def __getattr__(self, _name: str) -> Any:
        def fail(*_args: Any, **_kwargs: Any) -> None:
            raise EndpointConnectionError(endpoint_url="http://sandbox-aws:5000")

        return fail


def test_an_unreachable_simulator_is_a_503(
    app: FastAPI, db_client: TestClient, analyst: User
) -> None:
    down = Clients(_Unreachable(), _Unreachable(), _Unreachable(), _Unreachable())
    app.dependency_overrides[get_sandbox_clients] = lambda: down
    response = db_client.get("/api/sandbox", headers=bearer(analyst))
    assert response.status_code == 503
    assert "simulated AWS is not reachable" in response.json()["detail"]
    change = db_client.patch(
        "/api/sandbox/controls/ssh-open", headers=bearer(analyst), json={"insecure": False}
    )
    assert change.status_code == 503


def test_sandbox_routes_are_404_in_normal_mode(db_client: TestClient, analyst: User) -> None:
    assert get_settings().sandbox_aws_endpoint is None
    assert db_client.get("/api/sandbox", headers=bearer(analyst)).status_code == 404
    reset = db_client.post("/api/sandbox/reset", headers=bearer(analyst))
    assert reset.status_code == 404


@pytest.fixture
def sandbox_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("SANDBOX_AWS_ENDPOINT", "http://sandbox-aws:5000")
    monkeypatch.setenv("GUEST_EMAIL", "guest@demo.test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_about_reports_normal_mode(client: TestClient) -> None:
    body = client.get("/api/about").json()
    assert body["sandbox_mode"] is False and body["guest_access"] is False
    assert body["version"]


@pytest.mark.usefixtures("sandbox_env")
def test_about_reports_sandbox_mode_and_guest_access(client: TestClient) -> None:
    body = client.get("/api/about").json()
    assert body["sandbox_mode"] is True and body["guest_access"] is True
