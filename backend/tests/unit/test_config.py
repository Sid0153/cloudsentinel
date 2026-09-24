import pytest
from pydantic import ValidationError

from app.core.config import Settings
from tests.helpers import make_settings

_DB = "postgresql+psycopg://u:p@localhost/db"
_GOOD_KEY = "test-key-0123456789-abcdefghijklmnopq"


def _settings(**overrides: str) -> Settings:
    values = {"database_url": _DB, "secret_key": _GOOD_KEY, **overrides}
    return make_settings(**values)


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
        make_settings(database_url=_DB)


def test_missing_database_url_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        make_settings(secret_key=_GOOD_KEY)


def test_wildcard_cors_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(cors_origins="*")


def test_cors_origins_are_split_and_trimmed() -> None:
    settings = _settings(cors_origins="http://a.example , http://b.example")
    assert settings.cors_origin_list == ["http://a.example", "http://b.example"]


def test_docs_disabled_in_production() -> None:
    production = _settings(app_env="production", cors_origins="https://sentinel.example")
    assert production.docs_enabled is False
    assert _settings(app_env="development").docs_enabled is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"secret_key": "a" * 64},  # long, but trivially guessable
        {"database_url": "postgresql://u:p@localhost/db"},  # wrong driver
        {"database_url": "sqlite:///cloudsentinel.db"},
        {"app_env": "production", "cors_origins": "http://sentinel.example"},
        {"app_env": "production", "cors_origins": "https://ok.example", "log_level": "DEBUG"},
    ],
)
def test_unsafe_or_invalid_settings_are_rejected(overrides: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


def test_validation_errors_never_contain_the_submitted_secret() -> None:
    weak_key = "my-weak-key-12345"
    with pytest.raises(ValidationError) as error:
        _settings(secret_key=weak_key)
    assert weak_key not in str(error.value)
    assert "SECRET_KEY must be at least" in str(error.value)
