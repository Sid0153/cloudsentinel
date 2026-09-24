"""S3 bucket rules: public access and default encryption.

Public access is decided only from what the collectors read: the bucket ACL, the bucket
policy status reported by AWS (GetBucketPolicyStatus) and the Block Public Access settings of
the bucket and the account. Object ACLs, access points and cross-account (non-public) policies
are not examined.
"""

from typing import Any

from app.domain.resources import (
    NormalizedResource,
    PublicAccessBlock,
    ResourceType,
    S3BucketConfig,
)
from app.rules.model import Outcome, RuleContext, Severity, check, config_of

# ACL permissions that let the grantee change the bucket's contents or its ACL.
WRITE_PERMISSIONS = {"WRITE", "WRITE_ACP", "FULL_CONTROL"}


def block_setting_in_force(config: S3BucketConfig, setting: str) -> bool | None:
    """Whether a Block Public Access setting applies, from the bucket or the account level.

    True if either level has it on. None if neither is known to have it on and at least one
    level could not be read. A level with no configuration at all counts as "off".
    """
    levels: list[tuple[PublicAccessBlock | None, str]] = [
        (config.public_access_block, "public_access_block"),
        (config.account_public_access_block, "account_public_access_block"),
    ]
    values: list[bool | None] = []
    for block, check_name in levels:
        if check_name in config.unknown_checks:
            values.append(None)
        else:
            values.append(block is not None and bool(getattr(block, setting)))
    if True in values:
        return True
    if None in values:
        return None
    return False


def _grants_write(grants: list[str]) -> bool:
    return any(grant.split(":", 1)[-1] in WRITE_PERMISSIONS for grant in grants)


@check("CS-S3-001", ResourceType.S3_BUCKET)
def public_bucket(resource: NormalizedResource, context: RuleContext) -> Outcome:
    config = config_of(resource, S3BucketConfig)
    ignore_acls = block_setting_in_force(config, "ignore_public_acls")
    restrict_policy = block_setting_in_force(config, "restrict_public_buckets")
    evidence: dict[str, Any] = {}
    undecided: list[str] = []

    if "acl" in config.unknown_checks:
        undecided.append("the bucket ACL could not be read")
    elif config.acl_public_grants:
        if ignore_acls is None:
            undecided.append("public ACL grants exist, but IgnorePublicAcls could not be read")
        elif ignore_acls is False:
            evidence["public_acl_grants"] = config.acl_public_grants

    if config.policy_is_public is None or "policy_status" in config.unknown_checks:
        undecided.append("the bucket policy status could not be read")
    elif config.policy_is_public:
        if restrict_policy is None:
            undecided.append("the policy is public, but RestrictPublicBuckets could not be read")
        elif restrict_policy is False:
            evidence["public_policy"] = True

    if evidence:
        # Public evidence stands even if another check was undecided.
        evidence["ignore_public_acls_in_force"] = ignore_acls
        evidence["restrict_public_buckets_in_force"] = restrict_policy
        writable = _grants_write(evidence.get("public_acl_grants", []))
        evidence["public_write"] = writable
        return Outcome.failed(evidence, severity=Severity.CRITICAL if writable else Severity.HIGH)
    if undecided:
        return Outcome.unknown("; ".join(undecided))
    return Outcome.passed()


@check("CS-S3-002", ResourceType.S3_BUCKET)
def encryption_disabled(resource: NormalizedResource, context: RuleContext) -> Outcome:
    config = config_of(resource, S3BucketConfig)
    if config.encryption_configured is None or "encryption" in config.unknown_checks:
        return Outcome.unknown("the default encryption setting could not be read")
    if config.encryption_configured:
        return Outcome.passed()
    return Outcome.failed({"default_encryption": None})
