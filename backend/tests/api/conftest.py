"""Fixtures shared by the API tests that run full scans against moto."""

from collections.abc import Callable

import pytest
from sqlalchemy.orm import Session

from app.aws.session import build_session
from app.models.aws_account import AwsAccount
from app.models.scan import Scan
from app.models.user import Role, User
from app.rules.model import Rule
from app.scans.service import create_scan, execute_scan
from tests.aws.seed import Seeded, seed_environment
from tests.helpers import make_aws_account, make_user

RunScan = Callable[..., Scan]


@pytest.fixture
def analyst(db_session: Session) -> User:
    return make_user(db_session, Role.ANALYST)


@pytest.fixture
def viewer(db_session: Session) -> User:
    return make_user(db_session, Role.VIEWER)


@pytest.fixture
def account(db_session: Session) -> AwsAccount:
    return make_aws_account(db_session)


@pytest.fixture
def seeded(mocked_aws: None, policy_status: dict[str, bool]) -> Seeded:
    seeded = seed_environment()
    policy_status["cs-public-bucket"] = True  # moto cannot evaluate bucket policies
    return seeded


@pytest.fixture
def run_scan(db_session: Session, account: AwsAccount, analyst: User) -> RunScan:
    """Runs a complete scan synchronously in the test's database session."""

    def run(rules: list[Rule] | None = None) -> Scan:
        scan = create_scan(db_session, account.id, analyst.id)
        execute_scan(db_session, scan.id, build_session, rules)
        db_session.expire_all()
        return scan

    return run
