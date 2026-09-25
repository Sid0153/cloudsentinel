from fastapi import APIRouter

from app import __version__
from app.api.deps import SettingsDep
from app.schemas.about import AboutResponse

router = APIRouter(prefix="/about", tags=["about"])


@router.get("", response_model=AboutResponse)
def about(settings: SettingsDep) -> AboutResponse:
    """What the sign-in page needs to know before anyone signs in. No sign-in needed."""
    return AboutResponse(
        version=__version__,
        sandbox_mode=settings.sandbox_enabled,
        guest_access=settings.guest_email is not None,
    )
