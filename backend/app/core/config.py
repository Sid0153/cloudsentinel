"""Application settings, loaded from environment variables (and an optional .env file).

Nothing secret has a default value: a missing SECRET_KEY or DATABASE_URL stops the app at
startup instead of silently running with something guessable.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.schemas.validators import normalize_email

MIN_SECRET_KEY_LENGTH = 32
MIN_SECRET_KEY_DISTINCT_CHARS = 10  # rejects "aaaa..." and other obviously weak keys
DATABASE_URL_PREFIX = "postgresql+psycopg://"
# security-rules/rules/ at the repository root. The Docker image sets RULES_DIR instead.
DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "security-rules" / "rules"
# Hosts of real AWS endpoints. The sandbox endpoint must never be one of them.
AWS_HOST_SUFFIXES = ("amazonaws.com", "amazonaws.com.cn", "api.aws")


class Settings(BaseSettings):
    # Later files override earlier ones: backend/.env overrides the repo-root .env.
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",  # the shared .env also holds POSTGRES_* values used by docker compose
        # Validation errors must never echo a submitted value: it could be the secret key.
        hide_input_in_errors=True,
    )

    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    database_url: str
    secret_key: str  # signs access tokens (JWT)
    cors_origins: str = "http://localhost:5173"  # comma-separated list
    rules_dir: Path = DEFAULT_RULES_DIR  # rule metadata YAML files

    # Authentication tuning. The defaults are deliberate; change them only with a reason.
    access_token_expire_minutes: int = Field(default=15, ge=1, le=120)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    max_failed_logins: int = Field(default=5, ge=1)
    lockout_minutes: int = Field(default=15, ge=1)
    login_rate_limit_per_minute: int = Field(default=10, ge=1)
    scan_rate_limit_per_minute: int = Field(default=3, ge=1)  # scans started, per client IP
    sandbox_rate_limit_per_minute: int = Field(default=30, ge=1)  # sandbox changes, per IP

    # Sandbox mode (docs/sandbox.md): every AWS call goes to this simulated AWS (moto) with
    # fake credentials, never to real AWS. Unset means normal mode: real AWS.
    sandbox_aws_endpoint: str | None = None
    # Where the client address comes from (rate limits, audit log); see core/client_ip.py.
    # Either a header the hosting platform always sets (Render: True-Client-IP), or the number
    # of trusted proxies that append to X-Forwarded-For (docker compose: 1, nginx). Neither:
    # the direct peer address, and X-Forwarded-For is ignored.
    client_ip_header: str | None = None
    trusted_proxy_hops: int = Field(default=0, ge=0, le=5)
    # Diagnostics: log the forwarding headers of every request, to see what a hosting platform
    # really sends before choosing one of the two settings above. Off in normal operation.
    log_forwarding_headers: bool = False
    # Email of the shared guest account. When set, POST /api/auth/guest signs visitors in
    # as that user without a password (for public demos). The account must not be an ADMIN.
    guest_email: str | None = None

    @field_validator("secret_key")
    @classmethod
    def _secret_key_is_strong_enough(cls, value: str) -> str:
        if len(value) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters")
        if len(set(value)) < MIN_SECRET_KEY_DISTINCT_CHARS:
            raise ValueError("SECRET_KEY looks too simple; generate a random one")
        return value

    @field_validator("database_url")
    @classmethod
    def _database_url_uses_psycopg(cls, value: str) -> str:
        if not value.startswith(DATABASE_URL_PREFIX):
            raise ValueError(f"DATABASE_URL must start with {DATABASE_URL_PREFIX}")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _cors_has_no_wildcard(cls, value: str) -> str:
        # Cookies are used for refresh tokens, so a wildcard origin would be unsafe.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must list explicit origins, wildcards are not allowed")
        return value

    @field_validator("sandbox_aws_endpoint")
    @classmethod
    def _sandbox_endpoint_is_not_aws(cls, value: str | None) -> str | None:
        if not value:
            return None
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("SANDBOX_AWS_ENDPOINT must be an http(s) URL")
        host = parts.hostname.lower()
        if any(host == suffix or host.endswith("." + suffix) for suffix in AWS_HOST_SUFFIXES):
            raise ValueError("SANDBOX_AWS_ENDPOINT must point to the simulator, not to real AWS")
        return value.rstrip("/")

    @field_validator("client_ip_header")
    @classmethod
    def _client_ip_header_is_a_header_name(cls, value: str | None) -> str | None:
        if not value:
            return None
        if not all(c.isalnum() or c == "-" for c in value):
            raise ValueError("CLIENT_IP_HEADER must be a header name such as True-Client-IP")
        return value

    @field_validator("guest_email")
    @classmethod
    def _guest_email_is_valid(cls, value: str | None) -> str | None:
        return normalize_email(value) if value else None

    @model_validator(mode="after")
    def _one_client_ip_source(self) -> Self:
        if self.client_ip_header and self.trusted_proxy_hops:
            raise ValueError("Set CLIENT_IP_HEADER or TRUSTED_PROXY_HOPS, not both")
        return self

    @model_validator(mode="after")
    def _production_is_locked_down(self) -> Self:
        """Settings that are fine on a laptop but unsafe on a server."""
        if self.app_env != "production":
            return self
        insecure = [o for o in self.cors_origin_list if not o.startswith("https://")]
        if insecure:
            raise ValueError("In production every CORS_ORIGINS entry must use https://")
        if self.log_level == "DEBUG":
            raise ValueError("LOG_LEVEL=DEBUG is not allowed in production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def sandbox_enabled(self) -> bool:
        return self.sandbox_aws_endpoint is not None

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are off in production."""
        return self.app_env != "production"

    @property
    def cookie_secure(self) -> bool:
        """The refresh cookie is HTTPS-only in production (plain http works for local dev)."""
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    # The required fields are read from the environment, which mypy cannot see.
    return Settings()  # type: ignore[call-arg,unused-ignore]
