"""python -m app.cli check-config: clear, secret-free startup errors."""

from collections.abc import Iterator
from contextlib import nullcontext

import pytest
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from app import cli
from app.core.config import get_settings
from app.models.audit_log import AuditLog
from app.models.aws_account import AwsAccount
from app.models.user import Role, User
from app.services.rule_catalog import get_rule_catalog


@pytest.fixture(autouse=True)
def fresh_settings() -> Iterator[None]:
    """Settings are cached; each test reads the environment again."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_invalid_settings_are_listed_without_their_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SECRET_KEY", "short-secret-value")
    monkeypatch.setenv("DATABASE_URL", "mysql://root:hunter2@db/app")
    assert cli.main(["check-config"]) == 1
    errors = capsys.readouterr().err
    assert "SECRET_KEY: Value error, SECRET_KEY must be at least 32 characters" in errors
    assert "DATABASE_URL" in errors
    assert "short-secret-value" not in errors and "hunter2" not in errors


def test_unreachable_database_is_reported_without_connection_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Port 1 on localhost: nothing listens there, so the connection fails at once.
    url = "postgresql+psycopg://user:hunter2@127.0.0.1:1/db"
    unreachable = create_engine(url, connect_args={"connect_timeout": 2})
    monkeypatch.setattr(cli, "get_engine", lambda: unreachable)
    assert cli.main(["check-config"]) == 1
    errors = capsys.readouterr().err
    assert "Cannot connect to the database" in errors and "hunter2" not in errors


def test_valid_configuration_passes(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "get_engine", lambda: db_engine)
    assert cli.main(["check-config"]) == 0
    output = capsys.readouterr().out
    assert output.startswith("Configuration OK: APP_ENV=")
    assert f"{len(get_rule_catalog().rules)} rules, database reachable" in output


@pytest.fixture
def cli_db(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Session:
    """The commands use the rolled-back test session instead of opening their own."""
    monkeypatch.setattr(cli, "get_session_factory", lambda: lambda: nullcontext(db_session))
    return db_session


def test_create_guest_needs_guest_email(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["create-guest"]) == 1
    assert "GUEST_EMAIL is not set" in capsys.readouterr().err


def test_create_guest_is_idempotent_and_never_prints_a_password(
    cli_db: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUEST_EMAIL", "Guest@Demo.Test")
    assert cli.main(["create-guest", "--role", "VIEWER"]) == 0
    assert cli.main(["create-guest"]) == 0
    output = capsys.readouterr().out
    assert "Created guest account guest@demo.test (VIEWER)" in output
    assert "already exists" in output
    [guest] = cli_db.scalars(select(User).where(User.email == "guest@demo.test"))
    assert guest.role == Role.VIEWER
    assert guest.password_hash.startswith("$argon2")  # a real hash of a random password


def test_register_sandbox_account_needs_sandbox_mode(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["register-sandbox-account"]) == 1
    assert "SANDBOX_AWS_ENDPOINT is not set" in capsys.readouterr().err


def test_register_sandbox_account_is_idempotent_and_audited(
    cli_db: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SANDBOX_AWS_ENDPOINT", "http://sandbox-aws:5000")
    assert cli.main(["register-sandbox-account"]) == 0
    assert cli.main(["register-sandbox-account"]) == 0
    assert "already registered" in capsys.readouterr().out
    [account] = cli_db.scalars(select(AwsAccount).where(AwsAccount.account_id == "123456789012"))
    assert account.regions == ["us-east-1"] and account.role_arn is None
    [event] = cli_db.scalars(select(AuditLog).where(AuditLog.action == "AWS_ACCOUNT_REGISTERED"))
    assert event.actor_id is None and event.details["via"] == "cli"
