"""The recommended IAM policy must grant exactly what the collectors call: no more (least
privilege) and no less (a missing action would make a real scan silently lose coverage)."""

import ast
import json
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
POLICY = BACKEND.parent / "infrastructure" / "cloudsentinel-readonly-policy.json"

# (file, boto3 operation) -> IAM actions it needs. STS calls need no permission in this policy:
# GetCallerIdentity is always allowed, and permission to AssumeRole belongs to the identity
# that assumes the role (see docs/aws-permissions.md).
OPERATION_TO_ACTIONS: dict[tuple[str, str], set[str]] = {
    ("ec2.py", "describe_instances"): {"ec2:DescribeInstances"},
    ("ec2.py", "describe_security_groups"): {"ec2:DescribeSecurityGroups"},
    ("s3.py", "list_buckets"): {"s3:ListAllMyBuckets"},
    ("s3.py", "get_bucket_location"): {"s3:GetBucketLocation"},
    ("s3.py", "get_bucket_encryption"): {"s3:GetEncryptionConfiguration"},
    ("s3.py", "get_bucket_policy_status"): {"s3:GetBucketPolicyStatus"},
    ("s3.py", "get_bucket_acl"): {"s3:GetBucketAcl"},
    # Called on the s3 client (bucket level) and on the s3control client (account level).
    ("s3.py", "get_public_access_block"): {
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
    },
    ("iam.py", "generate_credential_report"): {"iam:GenerateCredentialReport"},
    ("iam.py", "get_credential_report"): {"iam:GetCredentialReport"},
    ("iam.py", "get_account_authorization_details"): {"iam:GetAccountAuthorizationDetails"},
    ("cloudtrail.py", "describe_trails"): {"cloudtrail:DescribeTrails"},
    ("cloudtrail.py", "get_trail_status"): {"cloudtrail:GetTrailStatus"},
    ("session.py", "get_caller_identity"): set(),
    ("session.py", "assume_role"): set(),
}
_OPERATION_PREFIXES = ("describe_", "get_", "list_", "generate_", "assume_")


def _aws_operations() -> set[tuple[str, str]]:
    """Every AWS API operation called in app/aws/, found by reading the code (AST)."""
    found: set[tuple[str, str]] = set()
    for path in (BACKEND / "app" / "aws").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            name = node.func.attr
            if name == "get_paginator" and node.args and isinstance(node.args[0], ast.Constant):
                found.add((path.name, str(node.args[0].value)))
            elif name.startswith(_OPERATION_PREFIXES) and name != "get_paginator":
                found.add((path.name, name))
    return found


def _granted() -> set[str]:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    granted: set[str] = set()
    for statement in policy["Statement"]:
        assert statement["Effect"] == "Allow"
        actions = statement["Action"]
        granted |= set(actions if isinstance(actions, list) else [actions])
    return granted


def test_every_aws_call_is_known() -> None:
    unknown = _aws_operations() - set(OPERATION_TO_ACTIONS)
    assert not unknown, f"new AWS calls {unknown}: map them here and update the IAM policy"


def test_policy_grants_exactly_what_the_code_calls() -> None:
    needed = set().union(*(OPERATION_TO_ACTIONS[op] for op in _aws_operations()))
    granted = _granted()
    assert granted - needed == set(), "the policy grants actions the code never uses"
    assert needed - granted == set(), "the code calls AWS APIs the policy does not allow"


def test_policy_is_read_only() -> None:
    for action in _granted():
        _service, operation = action.split(":")
        assert "*" not in action, f"wildcard action {action}"
        assert operation.startswith(("Get", "List", "Describe", "GenerateCredentialReport")), action
