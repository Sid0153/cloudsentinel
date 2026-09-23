from collections.abc import Iterator
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.database.session import get_db


class _WorkingSession:
    def execute(self, *args: Any, **kwargs: Any) -> None:
        return None


class _BrokenSession:
    def execute(self, *args: Any, **kwargs: Any) -> None:
        raise OperationalError("SELECT 1", {}, Exception("connection refused to db-host:5432"))


def _override_db(app: FastAPI, session: object) -> None:
    def _get_db() -> Iterator[object]:
        yield session

    app.dependency_overrides[get_db] = _get_db


def test_live_returns_ok(client: TestClient) -> None:
    response = client.get("/api/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": None}


def test_ready_ok_when_database_reachable(app: FastAPI, client: TestClient) -> None:
    _override_db(app, _WorkingSession())
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "up"}


def test_ready_returns_503_when_database_down(app: FastAPI, client: TestClient) -> None:
    _override_db(app, _BrokenSession())
    response = client.get("/api/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "down"}


def test_ready_does_not_leak_database_error_details(app: FastAPI, client: TestClient) -> None:
    _override_db(app, _BrokenSession())
    response = client.get("/api/health/ready")
    assert "connection refused" not in response.text
    assert "db-host" not in response.text
