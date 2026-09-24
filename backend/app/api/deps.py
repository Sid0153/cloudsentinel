from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.database.session import get_db

DbSession = Annotated[Session, Depends(get_db)]

# List endpoints return one page; this header carries the total number of matching rows.
TOTAL_COUNT_HEADER = "X-Total-Count"
SettingsDep = Annotated[Settings, Depends(get_settings)]
