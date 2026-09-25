"""The client address used by rate limits and the audit log must not be forgeable."""

import secrets
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.datastructures import Headers

from app.core.client_ip import resolve_client_ip
from app.core.config import Settings
from app.database.session import get_db
from app.main import create_app
from app.models.audit_log import AuditLog
from tests.helpers import make_settings

PEER = "10.0.0.5"


def _headers(**values: str | list[str]) -> Headers:
    raw: list[tuple[bytes, bytes]] = []
    for name, value in values.items():
        for item in value if isinstance(value, list) else [value]:
            raw.append((name.replace("_", "-").lower().encode(), item.encode()))
    return Headers(raw=raw)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, PEER),
        # One trusted proxy: only the entry it appended counts; the rest is client-controlled.
        ({"x_forwarded_for": "198.51.100.7"}, "198.51.100.7"),
        ({"x_forwarded_for": "1.2.3.4, 198.51.100.7"}, "198.51.100.7"),
        ({"x_forwarded_for": ["1.2.3.4", "198.51.100.7"]}, "198.51.100.7"),  # two header lines
        ({"x_forwarded_for": "1.2.3.4, not-an-ip"}, PEER),
        ({"x_forwarded_for": "2001:db8::1"}, "2001:db8::1"),
    ],
)
def test_one_trusted_proxy_uses_the_last_entry(
    headers: dict[str, str | list[str]], expected: str
) -> None:
    assert resolve_client_ip(PEER, _headers(**headers), header=None, proxy_hops=1) == expected


def test_two_trusted_proxies_use_the_second_entry_from_the_right() -> None:
    headers = _headers(x_forwarded_for="1.2.3.4, 198.51.100.7, 10.1.1.1")
    assert resolve_client_ip(PEER, headers, header=None, proxy_hops=2) == "198.51.100.7"
    too_short = _headers(x_forwarded_for="10.1.1.1")
    assert resolve_client_ip(PEER, too_short, header=None, proxy_hops=2) == PEER


def test_without_trusted_proxies_forwarded_headers_are_ignored() -> None:
    headers = _headers(x_forwarded_for="1.2.3.4", true_client_ip="5.6.7.8")
    assert resolve_client_ip(PEER, headers, header=None, proxy_hops=0) == PEER


def test_platform_header_is_used_and_x_forwarded_for_ignored() -> None:
    headers = _headers(true_client_ip="198.51.100.7", x_forwarded_for="1.2.3.4")
    assert resolve_client_ip(PEER, headers, header="True-Client-IP", proxy_hops=0) == "198.51.100.7"
    missing = _headers(x_forwarded_for="1.2.3.4")
    assert resolve_client_ip(PEER, missing, header="True-Client-IP", proxy_hops=0) == PEER
    garbage = _headers(true_client_ip="<script>")
    assert resolve_client_ip(PEER, garbage, header="True-Client-IP", proxy_hops=0) == PEER


def _settings(**values: Any) -> Settings:
    return make_settings(
        database_url="postgresql+psycopg://user@db/app",
        secret_key=secrets.token_urlsafe(32),
        **values,
    )


def test_only_one_source_may_be_configured() -> None:
    with pytest.raises(ValidationError):
        _settings(client_ip_header="True-Client-IP", trusted_proxy_hops=1)
    with pytest.raises(ValidationError):
        _settings(client_ip_header="True Client IP")  # not a header name


@pytest.fixture
def behind_nginx(db_session: Session) -> Iterator[TestClient]:
    """An app configured like docker compose (one trusted proxy), on the rolled-back session."""
    app = create_app(_settings(trusted_proxy_hops=1, login_rate_limit_per_minute=2))

    def _get_db() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as client:
        yield client


def _login_attempt(client: TestClient, forwarded_for: str) -> int:
    body = {"email": "nobody@example.com", "password": "wrong-password-123"}
    headers = {"X-Forwarded-For": forwarded_for}
    return client.post("/api/auth/login", json=body, headers=headers).status_code


def test_forged_forwarded_for_does_not_escape_the_rate_limit(
    behind_nginx: TestClient, db_session: Session
) -> None:
    # Each request claims a different origin on the left; nginx's entry on the right is the same.
    codes = [_login_attempt(behind_nginx, f"203.0.113.{i}, 198.51.100.7") for i in range(3)]
    assert codes == [401, 401, 429]
    ips = {row.ip_address for row in db_session.scalars(select(AuditLog))}
    assert ips == {"198.51.100.7"}  # the audit log records the real client, not the forgery


def test_different_clients_have_separate_budgets(behind_nginx: TestClient) -> None:
    assert [_login_attempt(behind_nginx, f"198.51.100.{i}") for i in range(3)] == [401] * 3
