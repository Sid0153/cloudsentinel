import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import Select, func, select

from app.api.deps import TOTAL_COUNT_HEADER, DbSession
from app.auth.deps import CurrentUser
from app.domain.resources import ResourceType
from app.models.resource import Resource
from app.schemas.errors import error_responses
from app.schemas.resource import ResourceDetail, ResourceSummary

router = APIRouter(prefix="/resources", tags=["resources"], responses=error_responses(401))


@router.get("", response_model=list[ResourceSummary])
def list_resources(
    _user: CurrentUser,
    db: DbSession,
    response: Response,
    aws_account_id: uuid.UUID | None = None,
    resource_type: ResourceType | None = None,
    region: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Resource]:
    def filtered(statement: Select[Any]) -> Select[Any]:
        if aws_account_id is not None:
            statement = statement.where(Resource.aws_account_id == aws_account_id)
        if resource_type is not None:
            statement = statement.where(Resource.resource_type == str(resource_type))
        if region is not None:
            statement = statement.where(Resource.region == region)
        return statement

    total = db.scalar(filtered(select(func.count()).select_from(Resource)))
    response.headers[TOTAL_COUNT_HEADER] = str(total or 0)
    statement = filtered(select(Resource)).order_by(
        Resource.resource_type, Resource.region, Resource.resource_id
    ).limit(limit).offset(offset)
    return list(db.scalars(statement))


@router.get(
    "/{resource_uuid}", response_model=ResourceDetail, responses=error_responses(404)
)
def get_resource(resource_uuid: uuid.UUID, _user: CurrentUser, db: DbSession) -> Resource:
    resource = db.get(Resource, resource_uuid)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return resource
