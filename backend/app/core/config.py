"""Application settings, loaded from environment variables (and an optional .env file).

Nothing secret has a default value: a missing SECRET_KEY or DATABASE_URL stops the app at
startup instead of silently running with something guessable.
"""

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_KEY_LENGTH = 32


class Settings(BaseSettings):
    # Later files override earlier ones: backend/.env overrides the repo-root .env.
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",  # the shared .env also holds POSTGRES_* values used by docker compose
    )

    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    database_url: str
    secret_key: str  # signs JWTs from Phase 3 onward
    cors_origins: str = "http://localhost:5173"  # comma-separated list

    @field_validator("secret_key")
    @classmethod
    def _secret_key_is_long_enough(cls, value: str) -> str:
        if len(value) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _cors_has_no_wildcard(cls, value: str) -> str:
        # Cookies are used for refresh tokens, so a wildcard origin would be unsafe.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must list explicit origins, wildcards are not allowed")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are off in production."""
        return self.app_env != "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg,unused-ignore]
