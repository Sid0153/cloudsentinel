"""A simplified "is this bucket policy public?" check, for the simulator only.

moto 5 does not implement S3 GetBucketPolicyStatus. Real AWS decides with a detailed
evaluation (some conditions, such as a fixed source VPC, make a wildcard principal
non-public). This version is deliberately simple: a policy is public if an Allow statement
names the principal "*" and has no Condition. That covers the cases the sandbox creates.
"""

import json
from typing import Any


def _principal_is_everyone(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        values = aws if isinstance(aws, list) else [aws]
        return "*" in values
    return False


def policy_is_public(policy_text: str | bytes | None) -> bool:
    if not policy_text:
        return False
    policy = json.loads(policy_text)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return any(
        statement.get("Effect") == "Allow"
        and _principal_is_everyone(statement.get("Principal"))
        and not statement.get("Condition")
        for statement in statements
    )


def policy_status_xml(is_public: bool) -> str:
    value = "true" if is_public else "false"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<PolicyStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<IsPublic>{value}</IsPublic></PolicyStatus>"
    )
