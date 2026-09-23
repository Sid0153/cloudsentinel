"""baseline (no tables yet)

Revision ID: 0001
Revises:
Create Date: 2026-09-24

Intentionally empty. It proves the migration pipeline works (creates the alembic_version
table) before any real schema exists. Tables arrive in Phase 3 onward.
"""

from collections.abc import Sequence

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
