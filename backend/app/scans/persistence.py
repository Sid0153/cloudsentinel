import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.resources import NormalizedResource, ResourceKey, resource_key
from app.models.resource import Resource


def upsert_resources(
    db: Session,
    aws_account_id: uuid.UUID,
    scan_id: uuid.UUID,
    resources: list[NormalizedResource],
    now: datetime,
) -> dict[ResourceKey, Resource]:
    """Inserts new resources and updates known ones. Returns the rows found by this scan.

    Loads the account's existing rows once, which is fine at portfolio scale (thousands of
    rows). A very large estate would want a bulk INSERT ... ON CONFLICT instead.
    """
    existing: dict[ResourceKey, Resource] = {
        (row.region, row.resource_type, row.resource_id): row
        for row in db.scalars(select(Resource).where(Resource.aws_account_id == aws_account_id))
    }
    seen: dict[ResourceKey, Resource] = {}
    for item in resources:
        key = resource_key(item)
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
        seen[key] = row
    db.flush()  # assigns IDs to new rows, which findings refer to
    return seen
