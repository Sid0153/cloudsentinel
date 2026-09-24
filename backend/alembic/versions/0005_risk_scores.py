"""risk scores on findings, risk summary on scans

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-24

Existing findings get a score the next time a scan detects them; until then it is NULL.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("risk_breakdown", JSONB(), nullable=True))
    op.create_index("ix_findings_risk_score", "findings", ["risk_score"])
    op.add_column(
        "scans",
        sa.Column("risk_summary", JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("scans", "risk_summary")
    op.drop_index("ix_findings_risk_score", table_name="findings")
    op.drop_column("findings", "risk_breakdown")
    op.drop_column("findings", "risk_score")
