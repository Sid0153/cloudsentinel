import logging
import re
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.client_ip import Network, forwarding_headers, resolve_client_ip
from app.core.logging import client_ip_var, request_id_var

logger = logging.getLogger(__name__)

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
        self,
        app: ASGIApp,
        *,
        proxy_hops: int = 0,
        trusted_networks: tuple[Network, ...] = (),
        log_forwarding: bool = False,
    ) -> None:
        super().__init__(app)
        self._proxy_hops = proxy_hops
        self._trusted_networks = trusted_networks
        self._log_forwarding = log_forwarding

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
            proxy_hops=self._proxy_hops,
            trusted_networks=self._trusted_networks,
        )
        request.state.client_ip = ip
        if self._log_forwarding:
            peer = request.client.host if request.client else None
            # %r quotes the values, so a client cannot inject line breaks into the log.
            logger.info(
                "Forwarding headers: %r -> client %s",
                forwarding_headers(peer, request.headers),
                ip,
            )
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
