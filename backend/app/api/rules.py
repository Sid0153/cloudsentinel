from fastapi import APIRouter

from app.auth.deps import CurrentUser
from app.schemas.errors import error_responses
from app.schemas.finding import RulePublic
from app.services.rule_catalog import get_rule_catalog

router = APIRouter(prefix="/rules", tags=["rules"], responses=error_responses(401))


@router.get("", response_model=list[RulePublic])
def list_rules(_user: CurrentUser) -> list[RulePublic]:
    """Every security rule CloudSentinel runs, with its explanation and remediation."""
    return [RulePublic.from_rule(rule) for rule in get_rule_catalog().rules]
