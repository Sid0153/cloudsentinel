"""IAM rules: console users without MFA, and overly broad permissions.

"Broad" follows the simple, documented pattern computed by the IAM normalizer: an Allow
statement with Action "*" or "service:*" on Resource "*", or the AWS-managed
AdministratorAccess policy. This is pattern matching, not a full IAM policy evaluation.
"""

from typing import Any

from app.domain.resources import (
    BroadStatement,
    IamRoleConfig,
    IamUserConfig,
    NormalizedResource,
    ResourceType,
)
from app.rules.model import Outcome, RuleContext, Severity, check, config_of

# Service-linked roles are created and managed by AWS services; their policies cannot be edited.
SERVICE_LINKED_ROLE_PATH = "/aws-service-role/"
MAX_STATEMENTS_IN_EVIDENCE = 20


def _statement(statement: BroadStatement) -> dict[str, Any]:
    return {
        "source": statement.source,
        "actions": statement.actions,
        "resources": statement.resources,
        "has_condition": statement.has_condition,
    }


def user_credentials(config: IamUserConfig) -> dict[str, Any]:
    """Whether anyone can sign in as this user (None: credential report unavailable)."""
    keys = [config.access_key_1_active, config.access_key_2_active]
    return {
        "console_password": config.password_enabled,
        "active_access_keys": None if None in keys else sum(1 for key in keys if key),
    }


def is_privileged(config: IamUserConfig | IamRoleConfig) -> bool:
    return config.uses_admin_managed_policy or bool(config.broad_statements)


@check("CS-IAM-001", ResourceType.IAM_USER)
def console_user_without_mfa(resource: NormalizedResource, context: RuleContext) -> Outcome:
    config = config_of(resource, IamUserConfig)
    if config.password_enabled is None:
        return Outcome.unknown("the IAM credential report was not available")
    if not config.password_enabled:
        return Outcome.passed()  # no console password: this rule does not apply
    if config.mfa_active is None:
        return Outcome.unknown("the MFA status was not in the credential report")
    if config.mfa_active:
        return Outcome.passed()

    privileged = is_privileged(config) if config.permissions_analyzed else None
    evidence = {
        "console_password": True,
        "mfa_active": False,
        "privileged": privileged,  # None: the user's policies could not be read
    }
    return Outcome.failed(evidence, severity=Severity.HIGH if privileged else Severity.MEDIUM)


@check("CS-IAM-002", ResourceType.IAM_USER, ResourceType.IAM_ROLE)
def overly_broad_permissions(resource: NormalizedResource, context: RuleContext) -> Outcome:
    config: IamUserConfig | IamRoleConfig
    if resource.resource_type == ResourceType.IAM_USER:
        config = config_of(resource, IamUserConfig)
        if not config.permissions_analyzed:
            return Outcome.unknown("the user's policies could not be read")
    else:
        config = config_of(resource, IamRoleConfig)
        if config.path.startswith(SERVICE_LINKED_ROLE_PATH):
            return Outcome.passed()  # managed by AWS, not by the account owner

    if not is_privileged(config):
        return Outcome.passed()

    full_admin = config.uses_admin_managed_policy or any(
        "*" in statement.actions and not statement.has_condition
        for statement in config.broad_statements
    )
    statements = config.broad_statements
    evidence: dict[str, Any] = {
        "administrator_access_policy": config.uses_admin_managed_policy,
        "full_admin": full_admin,
        "broad_statement_count": len(statements),
        "broad_statements": [_statement(s) for s in statements[:MAX_STATEMENTS_IN_EVIDENCE]],
    }
    if isinstance(config, IamUserConfig):
        evidence.update(user_credentials(config))
    return Outcome.failed(evidence, severity=Severity.HIGH if full_admin else Severity.MEDIUM)
