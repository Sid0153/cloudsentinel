"""Scan lifecycle: create, execute and clean up. Each step is a small, separately testable part."""

import logging
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.aws.common import AWS_ERRORS, error_label
from app.aws.session import SessionBuilder, get_caller_identity
from app.models.aws_account import AwsAccount
from app.models.scan import ACTIVE_STATUSES, Scan, ScanStatus
from app.scans.discovery import discover
from app.scans.persistence import upsert_resources

logger = logging.getLogger(__name__)

INTERRUPTED_MESSAGE = "Interrupted: the server restarted while this scan was queued or running"
INTERNAL_ERROR_MESSAGE = "Internal error during the scan (details are in the server log)"


class AwsAccountNotFoundError(Exception):
    pass


class ScanAlreadyActiveError(Exception):
    pass


class ScanFailedError(Exception):
    """A scan cannot continue. The message is shown to users, so it must be safe."""


def _now() -> datetime:
    return datetime.now(UTC)


def create_scan(db: Session, aws_account_id: uuid.UUID, triggered_by_id: uuid.UUID) -> Scan:
    # Locking the account row makes the "already running?" check and the insert atomic.
    account = db.get(AwsAccount, aws_account_id, with_for_update=True)
    if account is None:
        raise AwsAccountNotFoundError
    active = db.scalar(
        select(Scan.id).where(Scan.aws_account_id == account.id, Scan.status.in_(ACTIVE_STATUSES))
    )
    if active is not None:
        db.rollback()
        raise ScanAlreadyActiveError
    scan = Scan(aws_account_id=account.id, triggered_by_id=triggered_by_id)
    db.add(scan)
    db.commit()
    return scan


def _finish(db: Session, scan: Scan, status: ScanStatus, error: str | None = None) -> None:
    scan.status = status
    scan.error_summary = error
    scan.finished_at = _now()
    db.commit()


def _run(db: Session, scan: Scan, account: AwsAccount, build_session: SessionBuilder) -> None:
    try:
        session = build_session(account.role_arn, account.regions[0])
        identity = get_caller_identity(session)
    except AWS_ERRORS as exc:
        label = error_label("Connect", exc)
        raise ScanFailedError(f"Could not authenticate to AWS: {label}") from exc

    if identity.account_id != account.account_id:
        raise ScanFailedError(
            f"The AWS credentials belong to account {identity.account_id}, "
            f"not {account.account_id}. Nothing was scanned."
        )
    scan.caller_arn = identity.arn
    db.commit()

    discovery = discover(session, identity, list(account.regions))
    counts = upsert_resources(db, account.id, scan.id, discovery.resources, _now())
    scan.resource_counts = counts
    scan.resource_count = sum(counts.values())
    scan.coverage = discovery.coverage
    _finish(
        db, scan, ScanStatus.COMPLETED if discovery.complete else ScanStatus.COMPLETED_WITH_ERRORS
    )


def execute_scan(db: Session, scan_id: uuid.UUID, build_session: SessionBuilder) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status != ScanStatus.PENDING:
        logger.warning("Scan %s is missing or not pending; not running it", scan_id)
        return
    account = db.get(AwsAccount, scan.aws_account_id)
    if account is None:
        _finish(db, scan, ScanStatus.FAILED, "The AWS account was removed")
        return

    scan.status = ScanStatus.RUNNING
    scan.started_at = _now()
    db.commit()
    logger.info("Scan %s started for AWS account record %s", scan.id, account.id)

    try:
        _run(db, scan, account, build_session)
    except ScanFailedError as exc:
        db.rollback()
        _finish(db, scan, ScanStatus.FAILED, str(exc))
    except Exception:
        logger.exception("Scan %s failed unexpectedly", scan_id)
        db.rollback()
        _finish(db, scan, ScanStatus.FAILED, INTERNAL_ERROR_MESSAGE)
    logger.info("Scan %s finished with status %s", scan.id, scan.status)


SessionScope = Callable[[], AbstractContextManager[Session]]


def run_scan_job(scan_id: uuid.UUID, session_scope: SessionScope, build: SessionBuilder) -> None:
    """Background-task entry point: uses its own database session, not the request's."""
    with session_scope() as db:
        execute_scan(db, scan_id, build)


def reconcile_stale_scans(db: Session) -> int:
    """Marks scans left PENDING/RUNNING by a previous process as FAILED.

    Background tasks live inside the API process, so a restart loses them. This runs at
    startup (single backend instance assumed; see docs/architecture.md).
    """
    result = db.execute(
        update(Scan)
        .where(Scan.status.in_(ACTIVE_STATUSES))
        .values(status=ScanStatus.FAILED, error_summary=INTERRUPTED_MESSAGE, finished_at=_now())
    )
    db.commit()
    return int(getattr(result, "rowcount", 0) or 0)
