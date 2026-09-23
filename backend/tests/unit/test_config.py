import pytest
from pydantic import ValidationError

from app.core.config import Settings

_DB = "postgresql+psycopg://u:p@localhost/db"
_GOOD_KEY = "k" * 40


def _settings(**overrides: str) -> Settings:
    values = {"database_url": _DB, "secret_key": _GOOD_KEY, **overrides}
    return Settings(_env_file=None, **values)


def test_valid_settings_load() -> None:
    settings = _settings()
    assert settings.app_env in {"development", "test", "production"}
    assert settings.docs_enabled is (settings.app_env != "production")


def test_short_secret_key_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(secret_key="too-short")


def test_missing_secret_key_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url=_DB)


def test_missing_database_url_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, secret_key=_GOOD_KEY)


def test_wildcard_cors_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(cors_origins="*")


def test_cors_origins_are_split_and_trimmed() -> None:
    settings = _settings(cors_origins="http://a.example , http://b.example")
    assert settings.cors_origin_list == ["http://a.example", "http://b.example"]


def test_docs_disabled_in_production() -> None:
    assert _settings(app_env="production").docs_enabled is False
    assert _settings(app_env="development").docs_enabled is True
