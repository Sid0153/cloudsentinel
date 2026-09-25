"""Sandbox mode glue: builds clients for the simulated AWS, only when sandbox mode is on."""

import logging

from app.aws.common import AWS_ERRORS
from app.aws.sandbox import SANDBOX_REGION, Clients, clients_for, ensure_environment
from app.aws.session import SandboxSession
from app.core.config import Settings

logger = logging.getLogger(__name__)


def sandbox_clients(settings: Settings) -> Clients | None:
    """Clients for the simulator, or None in normal mode (never clients for real AWS)."""
    if settings.sandbox_aws_endpoint is None:
        return None
    return clients_for(SandboxSession(settings.sandbox_aws_endpoint, SANDBOX_REGION))


def prepare_for_scan(settings: Settings) -> None:
    """Recreates the sandbox environment if the simulator restarted and lost it.

    Without this, a scan right after a restart would find an empty account and close every
    finding. Best effort: if the simulator is down, the scan itself reports the failure.
    """
    clients = sandbox_clients(settings)
    if clients is None:
        return
    try:
        if ensure_environment(clients):
            logger.info("Sandbox environment recreated before a scan")
    except AWS_ERRORS:
        logger.warning("Sandbox environment could not be prepared before a scan")
