"""python -m app.cli check-config: clear, secret-free startup errors."""

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine

from app import cli
from app.core.config import get_settings
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
