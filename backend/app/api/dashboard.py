import uuid

from fastapi import APIRouter

from app.api.deps import DbSession
from app.auth.deps import CurrentUser
from app.schemas.dashboard import DashboardSummary
from app.schemas.errors import error_responses
from app.services.dashboard import DashboardData, build_dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"], responses=error_responses(401))


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    _user: CurrentUser, db: DbSession, aws_account_id: uuid.UUID | None = None
) -> DashboardData:
    """Overall risk, counts and top risks, for one AWS account or all of them."""
    return build_dashboard(db, aws_account_id)
