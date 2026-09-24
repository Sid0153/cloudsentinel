import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import DbSession
from app.auth.deps import AdminUser
from app.models.user import User
from app.schemas.errors import error_responses
from app.schemas.user import UserCreate, UserPublic, UserUpdate
from app.services.user_service import (
    EmailAlreadyExistsError,
    SelfModificationError,
    UserNotFoundError,
    create_user,
    list_users,
    update_user,
)

router = APIRouter(prefix="/users", tags=["users"], responses=error_responses(401, 403))


@router.get("", response_model=list[UserPublic])
def list_all_users(
    _admin: AdminUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[User]:
    return list_users(db, limit, offset)


@router.post(
    "",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409),
)
def create_new_user(payload: UserCreate, _admin: AdminUser, db: DbSession) -> User:
    try:
        return create_user(db, payload.email, payload.password, payload.role, actor=_admin)
    except EmailAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists"
        ) from None


@router.patch("/{user_id}", response_model=UserPublic, responses=error_responses(400, 404))
def update_existing_user(
    user_id: uuid.UUID, payload: UserUpdate, admin: AdminUser, db: DbSession
) -> User:
    try:
        return update_user(db, admin, user_id, payload.role, payload.is_active)
    except SelfModificationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role or active status",
        ) from None
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        ) from None
