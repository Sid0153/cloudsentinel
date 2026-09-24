import enum
import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class ScanStatus(enum.StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"  # some data could not be read; see coverage
    FAILED = "FAILED"


ACTIVE_STATUSES = (ScanStatus.PENDING, ScanStatus.RUNNING)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    aws_account_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("aws_accounts.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        sa.Enum(ScanStatus, native_enum=False, length=30), default=ScanStatus.PENDING
    )
    triggered_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    caller_arn: Mapped[str | None] = mapped_column(sa.String(2048))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resource_count: Mapped[int] = mapped_column(default=0, server_default="0")
    # Snapshot per scan, so history stays accurate after later scans update the resources.
    resource_counts: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=sa.text("'{}'::jsonb")
    )
    # Per service: status (SUCCEEDED / PARTIAL / FAILED), item count and short error labels.
    coverage: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=sa.text("'{}'::jsonb")
    )
    error_summary: Mapped[str | None] = mapped_column(sa.String(500))
