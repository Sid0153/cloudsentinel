from typing import Any

from app.aws.normalizers.s3 import normalize_s3, public_acl_grants
from app.aws.raw import RawBucket, RawS3
from app.domain.resources import S3BucketConfig
from tests.fixtures.aws_raw import ENCRYPTION_RULES_KMS, FULL_BLOCK, PUBLIC_READ_GRANTS


def _config(
    bucket: RawBucket,
    account_block: dict[str, Any] | None = None,
    account_block_unknown: bool = False,
) -> S3BucketConfig:
    raw = RawS3(
        buckets=[bucket],
        account_public_access_block=account_block,
        account_public_access_block_unknown=account_block_unknown,
    )
    config = normalize_s3(raw)[0].config
    assert isinstance(config, S3BucketConfig)
    return config


def test_locked_down_bucket() -> None:
    bucket = RawBucket(
        name="secure",
        region="eu-west-1",
        encryption_rules=ENCRYPTION_RULES_KMS,
        public_access_block=FULL_BLOCK,
        policy_is_public=False,
    )
    config = _config(bucket, account_block=FULL_BLOCK)
    assert config.encryption_configured is True
    assert config.encryption_algorithm == "aws:kms"
    assert config.public_access_block is not None
    assert config.public_access_block.block_public_policy is True
    assert config.account_public_access_block is not None
    assert config.policy_is_public is False
    assert config.acl_public_grants == []
    assert config.unknown_checks == []


def test_exposed_bucket() -> None:
    bucket = RawBucket(
        name="exposed",
        region="us-east-1",
        encryption_rules=None,
        public_access_block=None,
        policy_is_public=True,
        acl_grants=PUBLIC_READ_GRANTS,
    )
    config = _config(bucket)
    assert config.encryption_configured is False
    assert config.public_access_block is None
    assert config.account_public_access_block is None
    assert config.policy_is_public is True
    assert config.acl_public_grants == ["AllUsers:READ"]


def test_failed_checks_are_reported_as_unknown_not_as_safe_or_unsafe() -> None:
    bucket = RawBucket(
        name="restricted",
        region="us-east-1",
        encryption_rules=None,
        public_access_block=None,
        policy_is_public=None,
        unknown_checks=["encryption", "policy_status"],
    )
    config = _config(bucket, account_block_unknown=True)
    assert config.encryption_configured is None
    assert config.policy_is_public is None
    assert config.unknown_checks == [
        "account_public_access_block",
        "encryption",
        "policy_status",
    ]


def test_authenticated_users_grant_counts_as_public() -> None:
    grants: list[dict[str, Any]] = [
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            },
            "Permission": "WRITE",
        },
        {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"}},
    ]
    assert public_acl_grants(grants) == ["AuthenticatedUsers:WRITE"]
