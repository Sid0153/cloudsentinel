import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import DbSession
from app.auth.deps import CurrentUser
from app.domain.resources import ResourceType
from app.models.resource import Resource
from app.schemas.resource import ResourceDetail, ResourceSummary

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("", response_model=list[ResourceSummary])
def list_resources(
    _user: CurrentUser,
    db: DbSession,
    aws_account_id: uuid.UUID | None = None,
    resource_type: ResourceType | None = None,
    region: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Resource]:
    statement = select(Resource)
    if aws_account_id is not None:
        statement = statement.where(Resource.aws_account_id == aws_account_id)
    if resource_type is not None:
        statement = statement.where(Resource.resource_type == str(resource_type))
    if region is not None:
        statement = statement.where(Resource.region == region)
    statement = statement.order_by(
        Resource.resource_type, Resource.region, Resource.resource_id
    ).limit(limit).offset(offset)
    return list(db.scalars(statement))


@router.get("/{resource_uuid}", response_model=ResourceDetail)
def get_resource(resource_uuid: uuid.UUID, _user: CurrentUser, db: DbSession) -> Resource:
    resource = db.get(Resource, resource_uuid)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return resource
