import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DbSession
from app.audit.events import AuditAction, AuditOutcome, TargetType
from app.audit.service import record
from app.auth.deps import AdminUser, CurrentUser
from app.aws.common import AWS_ERRORS, error_code
from app.aws.session import SessionBuilder, get_caller_identity
from app.models.aws_account import AwsAccount
from app.scans.deps import get_aws_session_builder
from app.schemas.aws_account import AwsAccountCreate, AwsAccountPublic, AwsAccountVerification
from app.schemas.errors import error_responses

router = APIRouter(
    prefix="/aws-accounts", tags=["aws-accounts"], responses=error_responses(401, 403)
)


@router.get("", response_model=list[AwsAccountPublic])
def list_aws_accounts(_user: CurrentUser, db: DbSession) -> list[AwsAccount]:
    return list(db.scalars(select(AwsAccount).order_by(AwsAccount.name)))


@router.post(
    "",
    response_model=AwsAccountPublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409),
)
def create_aws_account(payload: AwsAccountCreate, admin: AdminUser, db: DbSession) -> AwsAccount:
    account = AwsAccount(**payload.model_dump(), created_by_id=admin.id)
    db.add(account)
    try:
        db.flush()  # the unique account ID is checked here; also assigns the row ID
        record(
            db,
            AuditAction.AWS_ACCOUNT_REGISTERED,
            actor=admin,
            target_type=TargetType.AWS_ACCOUNT,
            target_id=account.id,
            details={
                "account_id": account.account_id,
                "name": account.name,
                "regions": list(account.regions),
                "role_arn": account.role_arn,
            },
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="This AWS account is already registered"
        ) from None
    return account


@router.post(
    "/{aws_account_id}/verify",
    response_model=AwsAccountVerification,
    responses=error_responses(404, 502),
)
def verify_aws_account(
    aws_account_id: uuid.UUID,
    admin: AdminUser,
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
        record(
            db,
            AuditAction.AWS_ACCOUNT_VERIFIED,
            outcome=AuditOutcome.FAILURE,
            actor=admin,
            target_type=TargetType.AWS_ACCOUNT,
            target_id=account.id,
            details={"error": error_code(exc)},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not verify AWS access: {error_code(exc)}",
        ) from None
    matches = identity.account_id == account.account_id
    record(
        db,
        AuditAction.AWS_ACCOUNT_VERIFIED,
        outcome=AuditOutcome.SUCCESS if matches else AuditOutcome.FAILURE,
        actor=admin,
        target_type=TargetType.AWS_ACCOUNT,
        target_id=account.id,
        details={"matches": matches, "caller_account_id": identity.account_id},
    )
    db.commit()
    return AwsAccountVerification(
        expected_account_id=account.account_id,
        caller_account_id=identity.account_id,
        caller_arn=identity.arn,
        matches=matches,
    )
