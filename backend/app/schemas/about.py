from pydantic import BaseModel


class AboutResponse(BaseModel):
    version: str
    # Scans run against a simulated AWS (moto), not a real account.
    sandbox_mode: bool
    # POST /api/auth/guest is available.
    guest_access: bool
