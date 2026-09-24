from typing import Any

from app.aws.raw import RawS3
from app.domain.resources import (
    NormalizedResource,
    PublicAccessBlock,
    ResourceType,
    S3BucketConfig,
)

_PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}


def public_access_block(raw: dict[str, Any] | None) -> PublicAccessBlock | None:
    if raw is None:
        return None
    return PublicAccessBlock(
        block_public_acls=bool(raw.get("BlockPublicAcls", False)),
        ignore_public_acls=bool(raw.get("IgnorePublicAcls", False)),
        block_public_policy=bool(raw.get("BlockPublicPolicy", False)),
        restrict_public_buckets=bool(raw.get("RestrictPublicBuckets", False)),
    )


def public_acl_grants(grants: list[dict[str, Any]]) -> list[str]:
    """ACL grants to everyone ("AllUsers") or to any AWS account ("AuthenticatedUsers")."""
    found: list[str] = []
    for grant in grants:
        group = _PUBLIC_GROUPS.get(str(grant.get("Grantee", {}).get("URI", "")))
        if group is not None:
            found.append(f"{group}:{grant.get('Permission', 'UNKNOWN')}")
    return sorted(set(found))


def _encryption(
    rules: list[dict[str, Any]] | None, unknown: list[str]
) -> tuple[bool | None, str | None]:
    if "encryption" in unknown:
        return None, None
    if not rules:
        return False, None
    default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
    algorithm = default.get("SSEAlgorithm")
    return True, str(algorithm) if algorithm else None


def normalize_s3(raw: RawS3) -> list[NormalizedResource]:
    account_block = public_access_block(raw.account_public_access_block)
    resources: list[NormalizedResource] = []
    for bucket in raw.buckets:
        unknown = list(bucket.unknown_checks)
        if raw.account_public_access_block_unknown:
            unknown.append("account_public_access_block")
        configured, algorithm = _encryption(bucket.encryption_rules, unknown)
        resources.append(
            NormalizedResource(
                resource_type=ResourceType.S3_BUCKET,
                resource_id=bucket.name,
                region=bucket.region,
                name=bucket.name,
                config=S3BucketConfig(
                    encryption_configured=configured,
                    encryption_algorithm=algorithm,
                    public_access_block=public_access_block(bucket.public_access_block),
                    account_public_access_block=account_block,
                    policy_is_public=bucket.policy_is_public,
                    acl_public_grants=public_acl_grants(bucket.acl_grants),
                    unknown_checks=sorted(set(unknown)),
                ),
            )
        )
    return resources
