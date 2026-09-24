import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ResourceSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    aws_account_id: uuid.UUID
    region: str
    resource_type: str
    resource_id: str
    name: str | None
    first_seen: datetime
    last_seen: datetime
    last_scan_id: uuid.UUID | None


class ResourceDetail(ResourceSummary):
    config: dict[str, Any]
