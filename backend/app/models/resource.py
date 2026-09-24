import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class Resource(Base):
    """The latest known configuration of one AWS resource.

    Each scan updates the row in place (one row per resource, not per scan). Resources that
    disappear from AWS are kept; last_seen shows when they were last found.
    """

    __tablename__ = "resources"
    __table_args__ = (
        sa.UniqueConstraint(
            "aws_account_id", "region", "resource_type", "resource_id", name="uq_resources_identity"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    aws_account_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("aws_accounts.id", ondelete="CASCADE")
    )
    region: Mapped[str] = mapped_column(sa.String(32))
    resource_type: Mapped[str] = mapped_column(sa.String(64))
    resource_id: Mapped[str] = mapped_column(sa.String(1024))
    name: Mapped[str | None] = mapped_column(sa.String(1024))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    first_seen: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="SET NULL")
    )
