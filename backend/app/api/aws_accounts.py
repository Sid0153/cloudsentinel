import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DbSession
from app.auth.deps import AdminUser, CurrentUser
from app.aws.common import AWS_ERRORS, error_code
from app.aws.session import SessionBuilder, get_caller_identity
from app.models.aws_account import AwsAccount
from app.scans.deps import get_aws_session_builder
from app.schemas.aws_account import AwsAccountCreate, AwsAccountPublic, AwsAccountVerification

router = APIRouter(prefix="/aws-accounts", tags=["aws-accounts"])


@router.get("", response_model=list[AwsAccountPublic])
def list_aws_accounts(_user: CurrentUser, db: DbSession) -> list[AwsAccount]:
    return list(db.scalars(select(AwsAccount).order_by(AwsAccount.name)))


@router.post("", response_model=AwsAccountPublic, status_code=status.HTTP_201_CREATED)
def create_aws_account(payload: AwsAccountCreate, admin: AdminUser, db: DbSession) -> AwsAccount:
    account = AwsAccount(**payload.model_dump(), created_by_id=admin.id)
    db.add(account)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="This AWS account is already registered"
        ) from None
    return account


@router.post("/{aws_account_id}/verify", response_model=AwsAccountVerification)
def verify_aws_account(
    aws_account_id: uuid.UUID,
    _admin: AdminUser,
    db: DbSession,
    build_session: Annotated[SessionBuilder, Depends(get_aws_session_builder)],
) -> AwsAccountVerification:
    """Checks which AWS identity the backend's credentials resolve to. Read-only."""
    account = db.get(AwsAccount, aws_account_id)
    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AWS account not found")
    try:
        identity = get_caller_identity(build_session(account.role_arn, account.regions[0]))
    except AWS_ERRORS as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not verify AWS access: {error_code(exc)}",
        ) from None
    return AwsAccountVerification(
        expected_account_id=account.account_id,
        caller_account_id=identity.account_id,
        caller_arn=identity.arn,
        matches=identity.account_id == account.account_id,
    )
