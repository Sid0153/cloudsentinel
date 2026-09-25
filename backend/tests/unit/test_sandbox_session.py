"""Sandbox mode must never talk to real AWS or use real credentials."""

import secrets
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app.aws.common import BOTO_CONFIG
from app.aws.session import (
    SANDBOX_CREDENTIAL,
    SandboxSession,
    _drop_account_host_prefix,
    build_session,
)
from app.core.config import Settings, get_settings
from tests.helpers import make_settings

ENDPOINT = "http://sandbox-aws:5000"


def _settings(**values: Any) -> Settings:
    return make_settings(
        database_url="postgresql+psycopg://user@db/app",
        secret_key=secrets.token_urlsafe(32),  # generated: no key-like literal in the repo
        **values,
    )


@pytest.fixture
def sandbox_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("SANDBOX_AWS_ENDPOINT", ENDPOINT)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class _Captured(Exception):
    """Raised instead of sending, after recording where the request would have gone."""

    def __init__(self, url: str) -> None:
        super().__init__(url)
        self.url = url


def _capture_url(request: Any, **_kwargs: Any) -> None:
    raise _Captured(request.url)


def test_every_client_points_at_the_simulator_with_fake_credentials() -> None:
    # The test environment has AWS_ACCESS_KEY_ID=testing; the sandbox must not use it.
    sandbox = SandboxSession(ENDPOINT, "us-east-1")
    for service in ("sts", "ec2", "s3", "s3control", "iam", "cloudtrail"):
        client = sandbox.client(service, region_name="eu-west-1", config=BOTO_CONFIG)
        assert client.meta.endpoint_url == ENDPOINT
    credentials = sandbox._session.get_credentials()
    assert credentials.access_key == SANDBOX_CREDENTIAL
    assert credentials.secret_key == SANDBOX_CREDENTIAL


def test_the_scanners_client_settings_are_kept() -> None:
    client = SandboxSession(ENDPOINT, "us-east-1").client("s3", config=BOTO_CONFIG)
    assert client.meta.config.read_timeout == BOTO_CONFIG.read_timeout
    assert client.meta.config.retries == BOTO_CONFIG.retries
    assert client.meta.config.s3["addressing_style"] == "path"


def test_s3_control_requests_go_to_the_simulator_host() -> None:
    client = SandboxSession(ENDPOINT, "us-east-1").client("s3control")
    client.meta.events.register("before-send.s3-control", _capture_url)
    with pytest.raises(_Captured) as sent:
        client.get_public_access_block(AccountId="123456789012")
    assert sent.value.url.startswith(f"{ENDPOINT}/v20180820/configuration/publicAccessBlock")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://123456789012.sandbox-aws:5000/x", "http://sandbox-aws:5000/x"),
        ("http://123456789012.127.0.0.1:5055/x", "http://127.0.0.1:5055/x"),
        ("http://sandbox-aws:5000/x", "http://sandbox-aws:5000/x"),  # nothing to remove
        ("http://12345.sandbox-aws:5000/x", "http://12345.sandbox-aws:5000/x"),  # not an ID
    ],
)
def test_only_an_account_id_prefix_is_removed(url: str, expected: str) -> None:
    request = SimpleNamespace(url=url)
    _drop_account_host_prefix(request)
    assert request.url == expected


def test_normal_mode_uses_the_standard_credential_chain() -> None:
    session = build_session(None, "us-east-1")
    assert not isinstance(session, SandboxSession)
    assert session.get_credentials().access_key == "testing"  # from the environment


@pytest.mark.usefixtures("sandbox_mode")
def test_sandbox_mode_sessions_use_the_simulator() -> None:
    session = build_session(None, "eu-west-1")
    assert isinstance(session, SandboxSession) and session.endpoint == ENDPOINT


@pytest.mark.usefixtures("sandbox_mode")
def test_sandbox_mode_keeps_assumed_role_credentials_inside_the_simulator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temporary = {"AccessKeyId": "ASIA-FAKE", "SecretAccessKey": "fake", "SessionToken": "tok"}
    sts = SimpleNamespace(assume_role=lambda **_kwargs: {"Credentials": temporary})
    monkeypatch.setattr(SandboxSession, "client", lambda self, *_args, **_kwargs: sts)
    session = build_session("arn:aws:iam::123456789012:role/audit", "us-east-1")
    assert isinstance(session, SandboxSession) and session.endpoint == ENDPOINT
    assert session._session.get_credentials().access_key == "ASIA-FAKE"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://s3.amazonaws.com",
        "https://ec2.eu-west-1.amazonaws.com",
        "https://sts.cn-north-1.amazonaws.com.cn",
        "https://s3.dualstack.us-east-1.api.aws",
        "ftp://sandbox-aws:5000",
        "sandbox-aws:5000",
    ],
)
def test_the_sandbox_endpoint_cannot_be_real_aws_or_malformed(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        _settings(sandbox_aws_endpoint=endpoint)


def test_sandbox_endpoint_and_guest_email_are_normalized() -> None:
    settings = _settings(
        sandbox_aws_endpoint="http://sandbox-aws:5000/",
        guest_email=" Guest@Demo.Test ",
    )
    assert settings.sandbox_aws_endpoint == "http://sandbox-aws:5000"
    assert settings.sandbox_enabled
    assert settings.guest_email == "guest@demo.test"


def test_empty_values_mean_off() -> None:
    settings = _settings(sandbox_aws_endpoint="", guest_email="")
    assert not settings.sandbox_enabled and settings.guest_email is None


def test_sessions_share_one_loader_so_memory_stays_flat() -> None:
    # Each session would otherwise parse the AWS service descriptions again (several MB each).
    first = build_session(None, "us-east-1")._session.get_component("data_loader")
    second = build_session(None, "eu-west-1")._session.get_component("data_loader")
    sandbox = SandboxSession(ENDPOINT, "us-east-1")._session._session.get_component("data_loader")
    assert first is second is sandbox
