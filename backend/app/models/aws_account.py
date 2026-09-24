import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class AwsAccount(Base):
    """An AWS account CloudSentinel may scan. No credentials are stored here, ever.

    Credentials come from the standard AWS credential chain of the backend process; the
    optional role_arn is assumed from that identity.
    """

    __tablename__ = "aws_accounts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    account_id: Mapped[str] = mapped_column(sa.String(12), unique=True)
    name: Mapped[str] = mapped_column(sa.String(100))
    regions: Mapped[list[str]] = mapped_column(JSONB)
    role_arn: Mapped[str | None] = mapped_column(sa.String(2048))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
