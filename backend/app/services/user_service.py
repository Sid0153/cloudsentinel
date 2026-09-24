import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, TargetType
from app.audit.service import record
from app.auth.passwords import hash_password
from app.auth.service import revoke_all_for_user
from app.models.user import Role, User


class EmailAlreadyExistsError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class SelfModificationError(Exception):
    """Admins may not change their own role or active flag (prevents locking yourself out)."""


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def create_user(
    db: Session, email: str, password: str, role: Role, actor: User | None = None
) -> User:
    """actor is the admin creating the user, or None for the command-line create-admin."""
    if get_user_by_email(db, email) is not None:
        raise EmailAlreadyExistsError
    user = User(email=email, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()  # assigns the ID for the audit record
    record(
        db,
        AuditAction.USER_CREATED,
        actor=actor,
        target_type=TargetType.USER,
        target_id=user.id,
        details={"email": email, "role": str(role), "via": "api" if actor else "cli"},
    )
    try:
        db.commit()
    except IntegrityError:
        # Two requests created the same email at the same moment; the unique index won.
        db.rollback()
        raise EmailAlreadyExistsError from None
    return user


def list_users(db: Session, limit: int, offset: int) -> list[User]:
    statement = select(User).order_by(User.created_at, User.email).limit(limit).offset(offset)
    return list(db.scalars(statement))


def update_user(
    db: Session,
    actor: User,
    user_id: uuid.UUID,
    role: Role | None,
    is_active: bool | None,
) -> User:
    if actor.id == user_id:
        raise SelfModificationError
    user = db.get(User, user_id)
    if user is None:
        raise UserNotFoundError
    changes: dict[str, dict[str, object]] = {}
    if role is not None and role != user.role:
        changes["role"] = {"from": str(user.role), "to": str(role)}
        user.role = role
    if is_active is not None and is_active != user.is_active:
        changes["is_active"] = {"from": user.is_active, "to": is_active}
        user.is_active = is_active
        if not is_active:
            revoke_all_for_user(db, user.id)
    if changes:
        record(
            db,
            AuditAction.USER_UPDATED,
            actor=actor,
            target_type=TargetType.USER,
            target_id=user.id,
            details={"email": user.email, **changes},
        )
    db.commit()
    return user
