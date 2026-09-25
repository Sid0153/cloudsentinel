"""Sandbox mode: look at and change the simulated AWS environment (docs/sandbox.md).

Every route answers 404 unless SANDBOX_AWS_ENDPOINT is set. Nothing here can reach real AWS:
the clients always point at the simulator.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.deps import DbSession, SettingsDep
from app.api.limits import enforce_rate_limit
from app.audit.events import AuditAction, TargetType
from app.audit.service import record
from app.auth.deps import AnalystUser, CurrentUser
from app.aws.common import AWS_ERRORS
from app.aws.sandbox import (
    CONTROLS,
    CONTROLS_BY_KEY,
    SANDBOX_ACCOUNT_ID,
    SANDBOX_REGION,
    Clients,
    apply_defaults,
    ensure_environment,
    read_states,
)
from app.schemas.errors import error_responses
from app.schemas.sandbox import SandboxControlPublic, SandboxControlUpdate, SandboxState
from app.services.sandbox import sandbox_clients

router = APIRouter(
    prefix="/sandbox", tags=["sandbox"], responses=error_responses(401, 403, 404, 503)
)

_UNREACHABLE = "The simulated AWS is not reachable right now. Try again in a minute."


def get_sandbox_clients(settings: SettingsDep) -> Clients:
    """Overridden in tests with clients for moto's in-process mock."""
    clients = sandbox_clients(settings)
    if clients is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sandbox mode is off")
    return clients


SandboxClients = Annotated[Clients, Depends(get_sandbox_clients)]


@contextmanager
def _simulator_errors() -> Iterator[None]:
    try:
        yield
    except AWS_ERRORS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_UNREACHABLE
        ) from None


def _state(clients: Clients) -> SandboxState:
    ensure_environment(clients)
    states = read_states(clients)
    return SandboxState(
        account_id=SANDBOX_ACCOUNT_ID,
        region=SANDBOX_REGION,
        controls=[
            SandboxControlPublic(
                key=control.key,
                title=control.title,
                description=control.description,
                rule_id=control.rule_id,
                insecure=states[control.key],
                insecure_by_default=control.insecure_by_default,
            )
            for control in CONTROLS
        ],
    )


# The user parameter comes first in every route, so authentication and the role check run
# before the "sandbox mode is off" check: anonymous callers get 401, not 404.


@router.get("", response_model=SandboxState)
def get_sandbox(_user: CurrentUser, clients: SandboxClients) -> SandboxState:
    """The simulated AWS account and the current state of every switch."""
    with _simulator_errors():
        return _state(clients)


@router.patch(
    "/controls/{key}", response_model=SandboxControlPublic, responses=error_responses(429)
)
def update_control(
    key: str,
    payload: SandboxControlUpdate,
    user: AnalystUser,
    clients: SandboxClients,
    request: Request,
    db: DbSession,
) -> SandboxControlPublic:
    """Makes one setting insecure (or fixes it). Run a scan afterwards to see the effect."""
    control = CONTROLS_BY_KEY.get(key)
    if control is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown control")
    enforce_rate_limit(request, db, request.app.state.sandbox_limiter, actor=user, kind="sandbox")
    with _simulator_errors():
        ensure_environment(clients)
        control.set_insecure(clients, payload.insecure)
        insecure = control.is_insecure(clients)
    record(
        db,
        AuditAction.SANDBOX_CHANGED,
        actor=user,
        target_type=TargetType.SANDBOX_CONTROL,
        target_id=control.key,
        details={"insecure": insecure, "rule_id": control.rule_id},
    )
    db.commit()
    return SandboxControlPublic(
        key=control.key,
        title=control.title,
        description=control.description,
        rule_id=control.rule_id,
        insecure=insecure,
        insecure_by_default=control.insecure_by_default,
    )


@router.post("/reset", response_model=SandboxState, responses=error_responses(429))
def reset_sandbox(
    user: AnalystUser, clients: SandboxClients, request: Request, db: DbSession
) -> SandboxState:
    """Puts every switch back to its default state."""
    enforce_rate_limit(request, db, request.app.state.sandbox_limiter, actor=user, kind="sandbox")
    with _simulator_errors():
        ensure_environment(clients)
        apply_defaults(clients)
        state = _state(clients)
    record(db, AuditAction.SANDBOX_RESET, actor=user)
    db.commit()
    return state
