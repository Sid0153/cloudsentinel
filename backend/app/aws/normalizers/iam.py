"""IAM users and roles, with a deliberately simple permission check.

A statement counts as "broad" when it is an Allow with an action of "*" or "service:*" on
Resource "*". NotAction, NotResource, permission boundaries, SCPs and resource policies are
NOT analyzed, and AWS-managed policies are only recognized by name (AdministratorAccess).
"""

import json
from typing import Any
from urllib.parse import unquote

from app.aws.raw import RawIam
from app.domain.resources import (
    GLOBAL_REGION,
    BroadStatement,
    IamRoleConfig,
    IamUserConfig,
    NormalizedResource,
    ResourceType,
)

ADMIN_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ROOT_REPORT_ROW = "<root_account>"


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _load_document(document: Any) -> dict[str, Any]:
    """boto3 normally decodes policy documents; handle a URL-encoded JSON string too."""
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            loaded = json.loads(unquote(document))
        except ValueError:
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return {}


def find_broad_statements(document: Any, source: str) -> list[BroadStatement]:
    statements = _load_document(document).get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    found: list[BroadStatement] = []
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        wildcard_actions = [a for a in actions if a == "*" or a.endswith(":*")]
        if wildcard_actions and "*" in resources:
            found.append(
                BroadStatement(
                    source=source,
                    actions=wildcard_actions,
                    resources=resources,
                    has_condition="Condition" in statement,
                )
            )
    return found


def _bool_field(row: dict[str, str] | None, key: str) -> bool | None:
    """Credential report values are "true", "false", "N/A" or "not_supported"."""
    if row is None:
        return None
    value = row.get(key, "").lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


class _PolicyIndex:
    """Customer-managed policy documents by ARN, and group details by name."""

    def __init__(self, details: dict[str, list[dict[str, Any]]]) -> None:
        self.documents: dict[str, Any] = {}
        for policy in details.get("Policies", []):
            for version in policy.get("PolicyVersionList", []):
                if version.get("IsDefaultVersion"):
                    self.documents[str(policy["Arn"])] = version.get("Document")
        self.groups = {str(g["GroupName"]): g for g in details.get("GroupDetailList", [])}

    def analyze(
        self, inline: list[dict[str, Any]], attached: list[dict[str, Any]], prefix: str = ""
    ) -> tuple[list[BroadStatement], list[str], bool]:
        broad: list[BroadStatement] = []
        for policy in inline:
            source = f"{prefix}inline:{policy.get('PolicyName', '?')}"
            broad.extend(find_broad_statements(policy.get("PolicyDocument"), source))
        arns = [str(p["PolicyArn"]) for p in attached if "PolicyArn" in p]
        for arn in arns:
            if arn in self.documents:
                broad.extend(find_broad_statements(self.documents[arn], f"{prefix}managed:{arn}"))
        return broad, arns, ADMIN_MANAGED_POLICY_ARN in arns


def _user_from_details(
    user: dict[str, Any], report: dict[str, dict[str, str]] | None, index: _PolicyIndex
) -> NormalizedResource:
    name = str(user["UserName"])
    row = report.get(name) if report is not None else None
    broad, arns, admin = index.analyze(
        user.get("UserPolicyList", []), user.get("AttachedManagedPolicies", [])
    )
    groups = [str(g) for g in user.get("GroupList", [])]
    for group_name in groups:
        group = index.groups.get(group_name)
        if group is None:
            continue
        group_broad, _, group_admin = index.analyze(
            group.get("GroupPolicyList", []),
            group.get("AttachedManagedPolicies", []),
            prefix=f"group:{group_name}/",
        )
        broad.extend(group_broad)
        admin = admin or group_admin
    return NormalizedResource(
        resource_type=ResourceType.IAM_USER,
        resource_id=str(user["Arn"]),
        region=GLOBAL_REGION,
        name=name,
        config=IamUserConfig(
            password_enabled=_bool_field(row, "password_enabled"),
            mfa_active=_bool_field(row, "mfa_active"),
            access_key_1_active=_bool_field(row, "access_key_1_active"),
            access_key_2_active=_bool_field(row, "access_key_2_active"),
            permissions_analyzed=True,
            groups=groups,
            attached_policy_arns=arns,
            broad_statements=broad,
            uses_admin_managed_policy=admin,
        ),
    )


def _user_from_report(row: dict[str, str]) -> NormalizedResource:
    return NormalizedResource(
        resource_type=ResourceType.IAM_USER,
        resource_id=row["arn"],
        region=GLOBAL_REGION,
        name=row["user"],
        config=IamUserConfig(
            password_enabled=_bool_field(row, "password_enabled"),
            mfa_active=_bool_field(row, "mfa_active"),
            access_key_1_active=_bool_field(row, "access_key_1_active"),
            access_key_2_active=_bool_field(row, "access_key_2_active"),
            permissions_analyzed=False,
        ),
    )


def normalize_iam(raw: RawIam) -> list[NormalizedResource]:
    report: dict[str, dict[str, str]] | None = None
    if raw.credential_report is not None:
        # The root account row is skipped: CloudSentinel does not store root credential data.
        report = {
            row["user"]: row
            for row in raw.credential_report
            if row.get("user") and row.get("user") != ROOT_REPORT_ROW
        }

    details = raw.authorization_details
    if details is None:
        return [_user_from_report(row) for row in (report or {}).values()]

    index = _PolicyIndex(details)
    resources = [_user_from_details(user, report, index) for user in details["UserDetailList"]]
    for role in details["RoleDetailList"]:
        broad, arns, admin = index.analyze(
            role.get("RolePolicyList", []), role.get("AttachedManagedPolicies", [])
        )
        resources.append(
            NormalizedResource(
                resource_type=ResourceType.IAM_ROLE,
                resource_id=str(role["Arn"]),
                region=GLOBAL_REGION,
                name=str(role["RoleName"]),
                config=IamRoleConfig(
                    path=str(role.get("Path", "/")),
                    attached_policy_arns=arns,
                    broad_statements=broad,
                    uses_admin_managed_policy=admin,
                ),
            )
        )
    return resources
