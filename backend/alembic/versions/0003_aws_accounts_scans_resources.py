"""aws_accounts, scans and resources

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-24
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EMPTY_JSON = sa.text("'{}'::jsonb")


def _created_at() -> sa.Column[datetime]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "aws_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("regions", JSONB(), nullable=False),
        sa.Column("role_arn", sa.String(length=2048), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_aws_accounts_created_by_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_aws_accounts"),
        sa.UniqueConstraint("account_id", name="uq_aws_accounts_account_id"),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("aws_account_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("triggered_by_id", sa.Uuid(), nullable=True),
        sa.Column("caller_arn", sa.String(length=2048), nullable=True),
        _created_at(),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resource_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("resource_counts", JSONB(), server_default=_EMPTY_JSON, nullable=False),
        sa.Column("coverage", JSONB(), server_default=_EMPTY_JSON, nullable=False),
        sa.Column("error_summary", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(
            ["aws_account_id"],
            ["aws_accounts.id"],
            name="fk_scans_aws_account_id_aws_accounts",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["triggered_by_id"],
            ["users.id"],
            name="fk_scans_triggered_by_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_aws_account_id", "scans", ["aws_account_id"])

    op.create_table(
        "resources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("aws_account_id", sa.Uuid(), nullable=False),
        sa.Column("region", sa.String(length=32), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=1024), nullable=False),
        sa.Column("name", sa.String(length=1024), nullable=True),
        sa.Column("config", JSONB(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scan_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["aws_account_id"],
            ["aws_accounts.id"],
            name="fk_resources_aws_account_id_aws_accounts",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["last_scan_id"],
            ["scans.id"],
            name="fk_resources_last_scan_id_scans",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_resources"),
        sa.UniqueConstraint(
            "aws_account_id",
            "region",
            "resource_type",
            "resource_id",
            name="uq_resources_identity",
        ),
    )


def downgrade() -> None:
    op.drop_table("resources")
    op.drop_index("ix_scans_aws_account_id", table_name="scans")
    op.drop_table("scans")
    op.drop_table("aws_accounts")
