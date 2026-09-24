"""Login, refresh-token rotation and logout. All database work for sessions lives here."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth.passwords import verify_against_dummy, verify_password
from app.auth.tokens import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from app.core.config import Settings
from app.models.refresh_token import RefreshToken
from app.models.user import User


class InvalidCredentialsError(Exception):
    """Wrong email or password, locked or disabled account. Callers must not say which."""


class InvalidRefreshTokenError(Exception):
    """The refresh token is unknown, expired, revoked or belongs to a disabled user."""


def authenticate(db: Session, email: str, password: str, settings: Settings) -> User:
    now = datetime.now(UTC)
    # FOR UPDATE serializes concurrent attempts, so the failure counter cannot be skipped.
    user = db.scalar(select(User).where(User.email == email).with_for_update())

    if user is None:
        verify_against_dummy(password)
        raise InvalidCredentialsError

    if user.locked_until is not None and user.locked_until > now:
        verify_against_dummy(password)
        raise InvalidCredentialsError

    if not verify_password(user.password_hash, password):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.max_failed_logins:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            user.failed_login_count = 0
        db.commit()
        raise InvalidCredentialsError

    if not user.is_active:
        raise InvalidCredentialsError

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()
    return user


def _new_refresh_token(db: Session, user_id: uuid.UUID, settings: Settings) -> str:
    plain = generate_refresh_token()
    db.add(
        RefreshToken(
            user_id=user_id,
            token_hash=hash_refresh_token(plain),
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    return plain


def _access_token(user: User, settings: Settings) -> str:
    return create_access_token(
        user.id, settings.secret_key, timedelta(minutes=settings.access_token_expire_minutes)
    )


def start_session(db: Session, user: User, settings: Settings) -> tuple[str, str]:
    """Returns (access_token, refresh_token)."""
    refresh_token = _new_refresh_token(db, user.id, settings)
    db.commit()
    return _access_token(user, settings), refresh_token


def revoke_all_for_user(db: Session, user_id: uuid.UUID, now: datetime | None = None) -> None:
    """Marks every active refresh token of the user as revoked. The caller commits."""
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or datetime.now(UTC))
    )


def rotate_session(
    db: Session, presented_token: str, settings: Settings
) -> tuple[User, str, str]:
    """Exchanges a refresh token for a new pair. Returns (user, access_token, refresh_token)."""
    now = datetime.now(UTC)
    row = db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_refresh_token(presented_token))
        .with_for_update()
    )
    if row is None:
        raise InvalidRefreshTokenError

    if row.revoked_at is not None:
        # A token that was already rotated or revoked is being replayed. Assume it was
        # stolen and end every session of this user.
        revoke_all_for_user(db, row.user_id, now)
        db.commit()
        raise InvalidRefreshTokenError

    if row.expires_at <= now:
        raise InvalidRefreshTokenError

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise InvalidRefreshTokenError

    row.revoked_at = now
    new_refresh_token = _new_refresh_token(db, user.id, settings)
    db.commit()
    return user, _access_token(user, settings), new_refresh_token


def revoke_refresh_token(db: Session, presented_token: str) -> None:
    row = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(presented_token))
    )
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        db.commit()
