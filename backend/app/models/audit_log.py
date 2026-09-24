import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class AuditLog(Base):
    """One security-relevant event. Append-only: a database trigger (migration 0006) rejects
    UPDATE, DELETE and TRUNCATE on this table.

    The actor reference has no ON DELETE action on purpose: a user who appears in the audit
    log cannot be deleted, only deactivated (CloudSentinel never deletes users).
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    action: Mapped[str] = mapped_column(sa.String(64), index=True)
    outcome: Mapped[str] = mapped_column(sa.String(16))  # SUCCESS or FAILURE
    # None: nobody signed in (e.g. a failed login) or the system itself (e.g. a scan finishing).
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"), index=True)
    actor_email: Mapped[str | None] = mapped_column(sa.String(254))  # as it was at the time
    target_type: Mapped[str | None] = mapped_column(sa.String(32))
    target_id: Mapped[str | None] = mapped_column(sa.String(64))
    ip_address: Mapped[str | None] = mapped_column(sa.String(45))
    request_id: Mapped[str | None] = mapped_column(sa.String(64))
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=sa.text("'{}'::jsonb")
    )
