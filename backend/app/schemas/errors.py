"""Error responses, declared on the routes so the OpenAPI document lists them."""

from typing import Any

from pydantic import BaseModel


class ErrorMessage(BaseModel):
    detail: str


_DESCRIPTIONS = {
    400: "The request is not allowed in this state (see the detail message)",
    401: "Not signed in, or the access token expired",
    403: "Signed in, but your role does not allow this",
    404: "Not found",
    409: "Conflicts with the current state (see the detail message)",
    429: "Too many attempts; retry after the Retry-After header",
    502: "AWS could not be reached or refused the request",
    503: "The simulated AWS (sandbox mode) is not reachable right now",
}


def error_responses(*codes: int) -> dict[int | str, dict[str, Any]]:
    """OpenAPI `responses` entries for the given status codes."""
    return {code: {"model": ErrorMessage, "description": _DESCRIPTIONS[code]} for code in codes}
