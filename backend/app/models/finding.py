import enum
import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class FindingStatus(enum.StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"  # known and accepted for now; still detected
    RESOLVED = "RESOLVED"  # fixed (confirmed by a scan, or marked by an analyst)
    FALSE_POSITIVE = "FALSE_POSITIVE"  # an analyst decided the finding is wrong


# Statuses that mean "still needs attention". Only these are closed automatically when a
# later scan confirms the problem is gone.
ACTIVE_FINDING_STATUSES = (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED)


class Finding(Base):
    """One problem (one rule on one resource), tracked across scans.

    The fingerprint identifies the problem, so a re-scan updates the same row instead of
    creating a duplicate. first_detected / last_detected show its history.
    """

    __tablename__ = "findings"
    __table_args__ = (
        sa.UniqueConstraint("aws_account_id", "fingerprint", name="uq_findings_fingerprint"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    aws_account_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("aws_accounts.id", ondelete="CASCADE")
    )
    resource_uuid: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("resources.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(sa.String(64))  # SHA-256 hex

    rule_id: Mapped[str] = mapped_column(sa.String(32), index=True)
    title: Mapped[str] = mapped_column(sa.String(200))
    category: Mapped[str] = mapped_column(sa.String(32))
    severity: Mapped[str] = mapped_column(sa.String(16), index=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB)

    # Copied from the resource (they are part of its identity and never change) so findings
    # can be filtered without a join.
    resource_type: Mapped[str] = mapped_column(sa.String(64))
    resource_id: Mapped[str] = mapped_column(sa.String(1024))
    region: Mapped[str] = mapped_column(sa.String(32))

    status: Mapped[FindingStatus] = mapped_column(
        sa.Enum(FindingStatus, native_enum=False, length=20),
        default=FindingStatus.OPEN,
        index=True,
    )
    status_note: Mapped[str | None] = mapped_column(sa.String(500))
    status_updated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    # None with a status_updated_at means the change was made by a scan, not a person.
    status_updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    first_detected: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    last_detected: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    first_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="SET NULL")
    )
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="SET NULL")
    )
