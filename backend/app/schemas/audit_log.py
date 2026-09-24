import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    action: str
    outcome: str
    actor_id: uuid.UUID | None  # None: anonymous (failed login) or the system (scan finished)
    actor_email: str | None
    target_type: str | None
    target_id: str | None
    ip_address: str | None
    request_id: str | None
    details: dict[str, Any]
