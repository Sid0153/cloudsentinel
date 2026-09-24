import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import DbSession
from app.auth.deps import AnalystUser, CurrentUser
from app.models.scan import Scan
from app.scans.deps import ScanRunner, get_scan_runner
from app.scans.service import AwsAccountNotFoundError, ScanAlreadyActiveError, create_scan
from app.schemas.scan import ScanCreate, ScanPublic

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanPublic, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    payload: ScanCreate,
    user: AnalystUser,
    db: DbSession,
    background_tasks: BackgroundTasks,
    runner: Annotated[ScanRunner, Depends(get_scan_runner)],
) -> Scan:
    """Queues a read-only scan and returns immediately. Poll GET /api/scans/{id} for progress."""
    try:
        scan = create_scan(db, payload.aws_account_id, user.id)
    except AwsAccountNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="AWS account not found"
        ) from None
    except ScanAlreadyActiveError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A scan is already queued or running for this AWS account",
        ) from None
    background_tasks.add_task(runner, scan.id)
    return scan


@router.get("", response_model=list[ScanPublic])
def list_scans(
    _user: CurrentUser,
    db: DbSession,
    aws_account_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Scan]:
    statement = select(Scan).order_by(Scan.created_at.desc(), Scan.id).limit(limit).offset(offset)
    if aws_account_id is not None:
        statement = statement.where(Scan.aws_account_id == aws_account_id)
    return list(db.scalars(statement))


@router.get("/{scan_id}", response_model=ScanPublic)
def get_scan(scan_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan
