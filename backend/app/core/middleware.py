import re
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.client_ip import resolve_client_ip
from app.core.logging import client_ip_var, request_id_var

# Only accept a caller-supplied request ID if it is short and boring; otherwise a client
# could inject newlines or huge strings into our logs.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")
_DOCS_PREFIX = "/api/docs"


def client_ip(request: Request) -> str:
    """The client address worked out by RequestContextMiddleware (see core/client_ip.py)."""
    resolved = getattr(request.state, "client_ip", None)
    if isinstance(resolved, str):
        return resolved
    return request.client.host if request.client else "unknown"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attaches a request ID, the client address and baseline security headers."""

    def __init__(
        self, app: ASGIApp, *, client_ip_header: str | None = None, proxy_hops: int = 0
    ) -> None:
        super().__init__(app)
        self._client_ip_header = client_ip_header
        self._proxy_hops = proxy_hops

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _SAFE_REQUEST_ID.match(supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        token = request_id_var.set(request_id)
        ip = resolve_client_ip(
            request.client.host if request.client else None,
            request.headers,
            header=self._client_ip_header,
            proxy_hops=self._proxy_hops,
        )
        request.state.client_ip = ip
        ip_token = client_ip_var.set(ip)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
            client_ip_var.reset(ip_token)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api") and not request.url.path.startswith(_DOCS_PREFIX):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
            )
        return response
