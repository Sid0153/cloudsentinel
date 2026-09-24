"""findings, and finding/rule summaries on scans

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EMPTY_JSON = sa.text("'{}'::jsonb")


def upgrade() -> None:
    op.add_column(
        "scans", sa.Column("finding_count", sa.Integer(), server_default="0", nullable=False)
    )
    op.add_column(
        "scans", sa.Column("finding_counts", JSONB(), server_default=_EMPTY_JSON, nullable=False)
    )
    op.add_column(
        "scans", sa.Column("rule_results", JSONB(), server_default=_EMPTY_JSON, nullable=False)
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("aws_account_id", sa.Uuid(), nullable=False),
        sa.Column("resource_uuid", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("evidence", JSONB(), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=1024), nullable=False),
        sa.Column("region", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("status_note", sa.String(length=500), nullable=True),
        sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_updated_by_id", sa.Uuid(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_detected", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_detected", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_scan_id", sa.Uuid(), nullable=True),
        sa.Column("last_scan_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["aws_account_id"],
            ["aws_accounts.id"],
            name="fk_findings_aws_account_id_aws_accounts",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["resource_uuid"],
            ["resources.id"],
            name="fk_findings_resource_uuid_resources",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["status_updated_by_id"],
            ["users.id"],
            name="fk_findings_status_updated_by_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["first_scan_id"],
            ["scans.id"],
            name="fk_findings_first_scan_id_scans",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["last_scan_id"],
            ["scans.id"],
            name="fk_findings_last_scan_id_scans",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.UniqueConstraint("aws_account_id", "fingerprint", name="uq_findings_fingerprint"),
    )
    op.create_index("ix_findings_resource_uuid", "findings", ["resource_uuid"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])


def downgrade() -> None:
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_rule_id", table_name="findings")
    op.drop_index("ix_findings_resource_uuid", table_name="findings")
    op.drop_table("findings")
    op.drop_column("scans", "rule_results")
    op.drop_column("scans", "finding_counts")
    op.drop_column("scans", "finding_count")
