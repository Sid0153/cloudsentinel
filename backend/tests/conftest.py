import os

# Must run before app modules are imported.
# Tests never use a DATABASE_URL inherited from the developer's shell: they use
# TEST_DATABASE_URL (a scratch database) or, without it, a placeholder that nothing connects to.
_TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
os.environ["DATABASE_URL"] = (
    _TEST_DATABASE_URL or "postgresql+psycopg://test:test@localhost:5432/test"
)
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-only-key-0123456789-abcdefghijklmnop")

# Fake AWS credentials for every test, so no test can ever reach a real AWS account even if
# the developer's machine has credentials configured. moto accepts any values.
os.environ.pop("AWS_PROFILE", None)
os.environ.update(
    {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_EC2_METADATA_DISABLED": "true",
    }
)

from collections.abc import Iterator  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from moto import mock_aws  # noqa: E402
from sqlalchemy import Engine, create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.aws.collectors import iam as iam_collector  # noqa: E402
from app.aws.collectors import s3 as s3_collector  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.database.session import get_db  # noqa: E402
from app.main import create_app  # noqa: E402

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    """A real PostgreSQL schema built by running the Alembic migrations."""
    if not _TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    get_settings.cache_clear()
    command.upgrade(Config(str(ALEMBIC_INI)), "head")
    engine = create_engine(_TEST_DATABASE_URL)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """A session inside a transaction that is rolled back after each test.

    Code under test may call commit(): with create_savepoint that only releases a
    SAVEPOINT, and the outer transaction (and all test data) is still discarded at the end.
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
        autoflush=False,
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def db_client(app: FastAPI, db_session: Session) -> Iterator[TestClient]:
    """A test client whose requests use the rolled-back test session."""

    def _get_db() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def mocked_aws(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """An in-memory fake of AWS (moto). Its account ID is always 123456789012."""
    monkeypatch.setattr(iam_collector, "REPORT_POLL_SECONDS", 0.0)
    with mock_aws():
        yield


@pytest.fixture
def policy_status(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """moto does not implement S3 GetBucketPolicyStatus, so tests decide the answer.

    Set policy_status["bucket-name"] = True to make a bucket's policy count as public.
    """
    verdicts: dict[str, bool] = {}

    def fake(client: object, bucket: str) -> bool | None:
        return verdicts.get(bucket, False)

    monkeypatch.setattr(s3_collector, "fetch_policy_is_public", fake)
    return verdicts
