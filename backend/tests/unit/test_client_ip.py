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

from app.core import middleware
from app.core.client_ip import forwarding_headers, parse_trusted_proxies, resolve_client_ip
from app.core.config import Settings
from app.database.session import get_db
from app.main import create_app
from app.models.audit_log import AuditLog
from tests.helpers import make_settings

PEER = "10.0.0.5"
VISITOR = "198.51.100.7"  # documentation address standing in for a real visitor
FORGED = "203.0.113.99"
RENDER = parse_trusted_proxies("private, cloudflare, 74.220.48.0/20")


def _headers(**values: str | list[str]) -> Headers:
    raw: list[tuple[bytes, bytes]] = []
    for name, value in values.items():
        for item in value if isinstance(value, list) else [value]:
            raw.append((name.replace("_", "-").lower().encode(), item.encode()))
    return Headers(raw=raw)


# --- TRUSTED_PROXY_HOPS (docker compose: nginx) -------------------------------------------


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, PEER),
        # One trusted proxy: only the entry it appended counts; the rest is client-controlled.
        ({"x_forwarded_for": VISITOR}, VISITOR),
        ({"x_forwarded_for": f"{FORGED}, {VISITOR}"}, VISITOR),
        ({"x_forwarded_for": [FORGED, VISITOR]}, VISITOR),  # two header lines
        ({"x_forwarded_for": f"{FORGED}, not-an-ip"}, PEER),
        ({"x_forwarded_for": "2001:db8::1"}, "2001:db8::1"),
    ],
)
def test_one_trusted_proxy_uses_the_last_entry(
    headers: dict[str, str | list[str]], expected: str
) -> None:
    assert resolve_client_ip(PEER, _headers(**headers), proxy_hops=1) == expected


def test_two_trusted_proxies_use_the_second_entry_from_the_right() -> None:
    headers = _headers(x_forwarded_for=f"{FORGED}, {VISITOR}, 10.1.1.1")
    assert resolve_client_ip(PEER, headers, proxy_hops=2) == VISITOR
    assert resolve_client_ip(PEER, _headers(x_forwarded_for="10.1.1.1"), proxy_hops=2) == PEER


def test_without_trusted_proxies_forwarded_headers_are_ignored() -> None:
    headers = _headers(x_forwarded_for=FORGED, true_client_ip=FORGED)
    assert resolve_client_ip(PEER, headers) == PEER


# --- TRUSTED_PROXIES (Render): rightmost untrusted address --------------------------------

# The chains below have the shape recorded on Render with LOG_FORWARDING_HEADERS (visitor
# address replaced): Render appends to what the client sent; through the static site's /api
# rewrite the request passes Cloudflare, Render's proxy (74.220.48.2) and Cloudflare again.
THROUGH_STATIC_SITE = (
    f"{FORGED},{VISITOR}, 162.158.42.194, 162.158.42.194,74.220.48.2, 162.158.170.4, 10.28.19.133"
)
DIRECT = f"{FORGED},{VISITOR}, 172.69.86.13, 10.25.19.29"


@pytest.mark.parametrize("chain", [THROUGH_STATIC_SITE, DIRECT])
def test_render_chains_resolve_to_the_visitor_not_the_forgery(chain: str) -> None:
    peer = chain.rsplit(",", 1)[1].strip()
    headers = _headers(x_forwarded_for=chain, true_client_ip="74.220.48.2")
    assert resolve_client_ip(peer, headers, trusted_networks=RENDER) == VISITOR


def test_an_untrusted_peer_is_the_client_whatever_the_headers_say() -> None:
    headers = _headers(x_forwarded_for=f"{FORGED}, 10.0.0.1")
    assert resolve_client_ip(VISITOR, headers, trusted_networks=RENDER) == VISITOR


def test_garbage_in_the_chain_stops_at_the_closest_known_address() -> None:
    headers = _headers(x_forwarded_for="not-an-ip, 162.158.1.1")
    assert resolve_client_ip(PEER, headers, trusted_networks=RENDER) == "162.158.1.1"


def test_a_chain_of_only_proxies_resolves_to_the_leftmost_proxy() -> None:
    headers = _headers(x_forwarded_for="10.9.9.9, 162.158.1.1")
    assert resolve_client_ip(PEER, headers, trusted_networks=RENDER) == "10.9.9.9"


def test_ipv6_visitors_and_proxies() -> None:
    headers = _headers(x_forwarded_for="2001:db8::7, 2606:4700::1")
    assert resolve_client_ip(PEER, headers, trusted_networks=RENDER) == "2001:db8::7"


def test_presets_expand_and_bad_networks_are_rejected() -> None:
    assert len(parse_trusted_proxies("private")) == 6
    assert len(parse_trusted_proxies("cloudflare, 74.220.48.0/20")) == 23
    for bad in ("74.220.48.1/20", "not-a-network", "999.0.0.0/8"):
        with pytest.raises(ValueError):
            parse_trusted_proxies(bad)


# --- Settings and the running app ----------------------------------------------------------


def _settings(**values: Any) -> Settings:
    return make_settings(
        database_url="postgresql+psycopg://user@db/app",
        secret_key=secrets.token_urlsafe(32),
        **values,
    )


def test_settings_validate_the_client_ip_source() -> None:
    assert _settings(trusted_proxies="private, cloudflare").trusted_networks
    assert _settings(trusted_proxies=" ").trusted_networks == ()
    with pytest.raises(ValidationError):
        _settings(trusted_proxies="private", trusted_proxy_hops=1)  # only one source
    with pytest.raises(ValidationError):
        _settings(trusted_proxies="everything")


def _app_client(db_session: Session, **values: Any) -> Iterator[TestClient]:
    app = create_app(_settings(login_rate_limit_per_minute=2, **values))

    def _get_db() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as client:
        yield client


@pytest.fixture
def behind_nginx(db_session: Session) -> Iterator[TestClient]:
    """Configured like docker compose (one trusted proxy), on the rolled-back session."""
    yield from _app_client(db_session, trusted_proxy_hops=1)


@pytest.fixture
def behind_render(db_session: Session) -> Iterator[TestClient]:
    """Configured like render.yaml, on the rolled-back session."""
    yield from _app_client(db_session, trusted_proxies="private, cloudflare, 74.220.48.0/20")


def _login_attempt(client: TestClient, forwarded_for: str) -> int:
    body = {"email": "nobody@example.com", "password": "wrong-password-123"}
    headers = {"X-Forwarded-For": forwarded_for}
    return client.post("/api/auth/login", json=body, headers=headers).status_code


def test_forged_forwarded_for_does_not_escape_the_rate_limit(
    behind_nginx: TestClient, db_session: Session
) -> None:
    # Each request claims a different origin on the left; nginx's entry on the right is the same.
    codes = [_login_attempt(behind_nginx, f"203.0.113.{i}, {VISITOR}") for i in range(3)]
    assert codes == [401, 401, 429]
    ips = {row.ip_address for row in db_session.scalars(select(AuditLog))}
    assert ips == {VISITOR}  # the audit log records the real client, not the forgery


def test_different_clients_have_separate_budgets(behind_nginx: TestClient) -> None:
    assert [_login_attempt(behind_nginx, f"198.51.100.{i}") for i in range(3)] == [401] * 3


def test_untrusted_peer_ignores_forwarded_for_entirely(behind_render: TestClient) -> None:
    # TestClient connects as "testclient", which is not an address in a trusted network, so
    # every X-Forwarded-For value is ignored and all attempts share one budget.
    codes = [_login_attempt(behind_render, f"198.51.100.{i}") for i in range(3)]
    assert codes == [401, 401, 429]


# --- Diagnostics ---------------------------------------------------------------------------


def test_forwarding_diagnostics_list_only_present_headers_truncated() -> None:
    headers = _headers(x_forwarded_for=["1.2.3.4", "5.6.7.8"], cf_connecting_ip="9.9.9.9", host="x")
    assert forwarding_headers(PEER, headers) == {
        "peer": PEER,
        "x-forwarded-for": "1.2.3.4, 5.6.7.8",
        "cf-connecting-ip": "9.9.9.9",
    }
    long_value = forwarding_headers(PEER, _headers(forwarded="a" * 500))["forwarded"]
    assert long_value is not None and len(long_value) == 200


def test_forwarding_diagnostics_are_logged_only_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # create_app() replaces the root log handlers, so record the middleware's messages directly.
    messages: list[str] = []
    monkeypatch.setattr(
        middleware.logger, "info", lambda message, *args: messages.append(message % args)
    )
    for enabled in (False, True):
        messages.clear()
        with TestClient(create_app(_settings(log_forwarding_headers=enabled))) as client:
            client.get("/api/health/live", headers={"X-Forwarded-For": "1.2.3.4"})
        logged = [message for message in messages if "Forwarding headers" in message]
        assert len(logged) == (1 if enabled else 0)
        if enabled:
            # Values are logged quoted (repr), so client-supplied text cannot fake log lines.
            assert "'x-forwarded-for': '1.2.3.4'" in logged[0]
