"""FastAPI dependencies that authenticate the caller and enforce roles on the server."""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditOutcome, TargetType
from app.audit.service import record
from app.auth.tokens import InvalidTokenError, decode_access_token
from app.core.config import Settings, get_settings
from app.database.session import get_db
from app.models.user import Role, User

_bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    if credentials is None:
        raise _unauthorized()
    try:
        user_id = decode_access_token(credentials.credentials, settings.secret_key)
    except InvalidTokenError:
        raise _unauthorized() from None

    # The user (and therefore the role) is loaded fresh on every request.
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    return user


def require_role(*allowed: Role) -> Callable[..., User]:
    def dependency(
        request: Request,
        user: Annotated[User, Depends(get_current_user)],
        db: Annotated[Session, Depends(get_db)],
    ) -> User:
        if user.role not in allowed:
            # A signed-in user probing routes above their role is worth an admin's attention.
            record(
                db,
                AuditAction.ACCESS_DENIED,
                outcome=AuditOutcome.FAILURE,
                actor=user,
                target_type=TargetType.ROUTE,
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "role": str(user.role),
                },
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )
        return user

    return dependency


CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]
AnalystUser = Annotated[User, Depends(require_role(Role.ANALYST, Role.ADMIN))]
