"""Runs the real Alembic migrations against PostgreSQL.

Skipped unless TEST_DATABASE_URL is set, e.g.
  TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/cloudsentinel_test pytest
Use a scratch database: the test downgrades to base (dropping all tables) and then
upgrades back to head so other tests can keep using the schema.
"""

import os

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

import app.models  # noqa: F401  (registers the ORM tables on Base.metadata)
from app.core.config import get_settings
from app.database.base import Base
from tests.conftest import ALEMBIC_INI

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set"),
]


def _config() -> Config:
    get_settings.cache_clear()
    return Config(str(ALEMBIC_INI))


def test_upgrade_and_downgrade() -> None:
    assert TEST_DATABASE_URL is not None
    config = _config()
    engine = create_engine(TEST_DATABASE_URL)
    try:
        command.upgrade(config, "head")
        tables = set(inspect(engine).get_table_names())
        expected = {
            "users",
            "refresh_tokens",
            "aws_accounts",
            "scans",
            "resources",
            "findings",
            "audit_logs",
        }
        assert expected | {"alembic_version"} <= tables
        with engine.connect() as connection:
            version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "0006"

        command.downgrade(config, "base")
        remaining = set(inspect(engine).get_table_names())
        assert remaining.isdisjoint(expected)
    finally:
        command.upgrade(config, "head")
        engine.dispose()


def test_models_match_the_migrations() -> None:
    """Fails if someone changes a model without writing the matching migration."""
    assert TEST_DATABASE_URL is not None
    command.upgrade(_config(), "head")
    engine = create_engine(TEST_DATABASE_URL)
    try:
        with engine.connect() as connection:
            differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    finally:
        engine.dispose()
    assert differences == []
