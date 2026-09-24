"""FastAPI dependencies for scanning, so tests can swap in fakes."""

import uuid
from collections.abc import Callable

from app.aws.session import SessionBuilder, build_session
from app.database.session import get_session_factory
from app.scans.service import run_scan_job

ScanRunner = Callable[[uuid.UUID], None]


def get_aws_session_builder() -> SessionBuilder:
    return build_session


def get_scan_runner() -> ScanRunner:
    def runner(scan_id: uuid.UUID) -> None:
        run_scan_job(scan_id, get_session_factory(), build_session)

    return runner
