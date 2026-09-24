import uuid
from collections import Counter
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.resources import NormalizedResource
from app.models.resource import Resource

ResourceKey = tuple[str, str, str]  # (region, resource_type, resource_id)


def upsert_resources(
    db: Session,
    aws_account_id: uuid.UUID,
    scan_id: uuid.UUID,
    resources: list[NormalizedResource],
    now: datetime,
) -> dict[str, int]:
    """Inserts new resources and updates known ones. Returns counts per resource type.

    Loads the account's existing rows once, which is fine at portfolio scale (thousands of
    rows). A very large estate would want a bulk INSERT ... ON CONFLICT instead.
    """
    existing: dict[ResourceKey, Resource] = {
        (row.region, row.resource_type, row.resource_id): row
        for row in db.scalars(select(Resource).where(Resource.aws_account_id == aws_account_id))
    }
    seen: set[ResourceKey] = set()
    for item in resources:
        key = (item.region, str(item.resource_type), item.resource_id)
        seen.add(key)
        row = existing.get(key)
        if row is None:
            row = Resource(
                aws_account_id=aws_account_id,
                region=item.region,
                resource_type=str(item.resource_type),
                resource_id=item.resource_id,
                first_seen=now,
            )
            db.add(row)
            existing[key] = row
        row.name = item.name
        row.config = item.config_dict()
        row.last_seen = now
        row.last_scan_id = scan_id
    return dict(Counter(resource_type for _, resource_type, _ in seen))
