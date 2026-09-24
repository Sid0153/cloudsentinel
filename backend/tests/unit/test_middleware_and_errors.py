from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import create_app
from tests.helpers import make_settings


def test_security_headers_present_on_api_responses(client: TestClient) -> None:
    response = client.get("/api/health/live")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_request_id_is_generated_when_absent(client: TestClient) -> None:
    response = client.get("/api/health/live")
    assert len(response.headers["X-Request-ID"]) >= 8


def test_safe_request_id_is_echoed(client: TestClient) -> None:
    response = client.get("/api/health/live", headers={"X-Request-ID": "abc12345-good-id"})
    assert response.headers["X-Request-ID"] == "abc12345-good-id"


def test_unsafe_request_id_is_replaced(client: TestClient) -> None:
    response = client.get("/api/health/live", headers={"X-Request-ID": "bad id with spaces!!"})
    assert response.headers["X-Request-ID"] != "bad id with spaces!!"


def test_unhandled_exception_returns_generic_500(app: FastAPI) -> None:
    def boom() -> None:
        raise RuntimeError("internal-detail-that-must-not-leak")

    app.add_api_route("/api/boom", boom)
    # raise_server_exceptions=False lets us see the response a real client would get.
    with TestClient(app, raise_server_exceptions=False) as test_client:
        response = test_client.get("/api/boom")
    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "Internal server error"
    assert "internal-detail-that-must-not-leak" not in response.text


def test_api_docs_disabled_in_production() -> None:
    settings = make_settings(
        app_env="production",
        database_url="postgresql+psycopg://u:p@localhost/db",
        secret_key="prod-like-key-0123456789-abcdefghijklmnop",
        cors_origins="https://sentinel.example",
    )
    with TestClient(create_app(settings)) as test_client:
        assert test_client.get("/api/docs").status_code == 404
        assert test_client.get("/api/openapi.json").status_code == 404
