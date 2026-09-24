"""S3 buckets and their access and encryption settings.

"Not configured" and "could not check" are kept apart: AWS returns a specific error code
when, for example, a bucket has no policy. Any other error marks the check as unknown.
"""

from typing import Any

from app.aws.common import (
    AWS_ERRORS,
    BOTO_CONFIG,
    GLOBAL_SERVICE_REGION,
    Boto3Session,
    Collected,
    error_code,
    error_label,
)
from app.aws.raw import RawBucket, RawS3
from app.domain.resources import UNKNOWN_REGION

NO_ENCRYPTION = "ServerSideEncryptionConfigurationNotFoundError"
NO_PUBLIC_ACCESS_BLOCK = "NoSuchPublicAccessBlockConfiguration"
NO_BUCKET_POLICY = "NoSuchBucketPolicy"


def bucket_region(location_constraint: Any) -> str:
    """GetBucketLocation returns None for us-east-1 and the legacy value "EU" for eu-west-1."""
    if not location_constraint:
        return "us-east-1"
    if location_constraint == "EU":
        return "eu-west-1"
    return str(location_constraint)


def fetch_policy_is_public(client: Any, bucket: str) -> bool | None:
    """AWS's own verdict on whether the bucket policy grants public access.

    Raises AWS errors other than "no policy". Returns None if AWS gave no verdict.
    """
    try:
        response = client.get_bucket_policy_status(Bucket=bucket)
    except AWS_ERRORS as exc:
        if error_code(exc) == NO_BUCKET_POLICY:
            return False
        raise
    is_public = response.get("PolicyStatus", {}).get("IsPublic")
    return is_public if isinstance(is_public, bool) else None


def _collect_bucket(client: Any, name: str, region: str, errors: list[str]) -> RawBucket:
    unknown: list[str] = []
    encryption_rules: list[dict[str, Any]] | None = None
    public_access_block: dict[str, Any] | None = None
    policy_is_public: bool | None = None
    acl_grants: list[dict[str, Any]] = []

    try:
        config = client.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]
        encryption_rules = list(config.get("Rules", []))
    except AWS_ERRORS as exc:
        if error_code(exc) != NO_ENCRYPTION:
            unknown.append("encryption")
            errors.append(f"{name}: {error_label('GetBucketEncryption', exc)}")

    try:
        response = client.get_public_access_block(Bucket=name)
        public_access_block = dict(response["PublicAccessBlockConfiguration"])
    except AWS_ERRORS as exc:
        if error_code(exc) != NO_PUBLIC_ACCESS_BLOCK:
            unknown.append("public_access_block")
            errors.append(f"{name}: {error_label('GetPublicAccessBlock', exc)}")

    try:
        policy_is_public = fetch_policy_is_public(client, name)
        if policy_is_public is None:
            unknown.append("policy_status")
    except AWS_ERRORS as exc:
        unknown.append("policy_status")
        errors.append(f"{name}: {error_label('GetBucketPolicyStatus', exc)}")

    try:
        acl_grants = list(client.get_bucket_acl(Bucket=name).get("Grants", []))
    except AWS_ERRORS as exc:
        unknown.append("acl")
        errors.append(f"{name}: {error_label('GetBucketAcl', exc)}")

    return RawBucket(
        name=name,
        region=region,
        encryption_rules=encryption_rules,
        public_access_block=public_access_block,
        policy_is_public=policy_is_public,
        acl_grants=acl_grants,
        unknown_checks=unknown,
    )


def collect_s3(session: Boto3Session, account_id: str) -> Collected[RawS3]:
    result = Collected(raw=RawS3())
    clients: dict[str, Any] = {}

    def client_for(region: str) -> Any:
        if region not in clients:
            clients[region] = session.client("s3", region_name=region, config=BOTO_CONFIG)
        return clients[region]

    s3control = session.client("s3control", region_name=GLOBAL_SERVICE_REGION, config=BOTO_CONFIG)
    try:
        response = s3control.get_public_access_block(AccountId=account_id)
        result.raw.account_public_access_block = dict(response["PublicAccessBlockConfiguration"])
    except AWS_ERRORS as exc:
        if error_code(exc) != NO_PUBLIC_ACCESS_BLOCK:
            result.raw.account_public_access_block_unknown = True
            result.errors.append(f"account: {error_label('GetPublicAccessBlock', exc)}")

    try:
        buckets = list(client_for(GLOBAL_SERVICE_REGION).list_buckets().get("Buckets", []))
    except AWS_ERRORS as exc:
        result.errors.append(error_label("ListBuckets", exc))
        return result

    for bucket in buckets:
        name = str(bucket["Name"])
        try:
            location = client_for(GLOBAL_SERVICE_REGION).get_bucket_location(Bucket=name)
            region = bucket_region(location.get("LocationConstraint"))
        except AWS_ERRORS as exc:
            region = UNKNOWN_REGION
            result.errors.append(f"{name}: {error_label('GetBucketLocation', exc)}")
        client = client_for(region if region != UNKNOWN_REGION else GLOBAL_SERVICE_REGION)
        result.raw.buckets.append(_collect_bucket(client, name, region, result.errors))

    result.items = len(result.raw.buckets)
    return result
