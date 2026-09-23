"""Runs the real Alembic migrations against PostgreSQL.

Skipped unless TEST_DATABASE_URL is set, e.g.
  TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/cloudsentinel_test pytest
Use a scratch database: the test upgrades to head and then downgrades to base.
"""

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.core.config import get_settings

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set"),
]

_ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def test_upgrade_and_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    assert TEST_DATABASE_URL is not None
    monkeypatch.setenv("DATABASE_URL", TEST_DATABASE_URL)
    get_settings.cache_clear()
    try:
        config = Config(str(_ALEMBIC_INI))
        command.upgrade(config, "head")

        engine = create_engine(TEST_DATABASE_URL)
        assert inspect(engine).has_table("alembic_version")
        with engine.connect() as connection:
            version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "0001"

        command.downgrade(config, "base")
        with engine.connect() as connection:
            remaining = connection.execute(text("SELECT count(*) FROM alembic_version")).scalar()
        assert remaining == 0
        engine.dispose()
    finally:
        get_settings.cache_clear()
