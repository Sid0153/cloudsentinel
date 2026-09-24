"""Collectors and normalizers against moto's in-memory AWS. No real AWS account is used."""

import json

import boto3
import pytest

from app.aws.collectors.cloudtrail import collect_cloudtrail
from app.aws.collectors.ec2 import collect_ec2
from app.aws.collectors.iam import collect_iam
from app.aws.collectors.s3 import collect_s3
from app.aws.normalizers.cloudtrail import normalize_cloudtrail
from app.aws.normalizers.ec2 import normalize_ec2
from app.aws.normalizers.iam import normalize_iam
from app.aws.normalizers.s3 import normalize_s3
from app.aws.session import build_session, get_caller_identity
from app.domain.resources import (
    CloudTrailConfig,
    IamRoleConfig,
    IamUserConfig,
    S3BucketConfig,
    SecurityGroupConfig,
)
from tests.aws.seed import seed_environment
from tests.helpers import MOTO_ACCOUNT_ID

REGIONS = ["us-east-1", "eu-west-1"]

pytestmark = pytest.mark.usefixtures("mocked_aws")


def test_caller_identity() -> None:
    identity = get_caller_identity(build_session(None, "us-east-1"))
    assert identity.account_id == MOTO_ACCOUNT_ID
    assert identity.arn.startswith("arn:aws:")


def test_assume_role_session_resolves_to_the_role() -> None:
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{MOTO_ACCOUNT_ID}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    boto3.client("iam", region_name="us-east-1").create_role(
        RoleName="CloudSentinelReadOnly", AssumeRolePolicyDocument=trust
    )
    role_arn = f"arn:aws:iam::{MOTO_ACCOUNT_ID}:role/CloudSentinelReadOnly"
    identity = get_caller_identity(build_session(role_arn, "us-east-1"))
    assert "assumed-role/CloudSentinelReadOnly" in identity.arn


def test_ec2_open_ssh_group_attached_to_an_instance() -> None:
    seeded = seed_environment()
    collected = collect_ec2(build_session(None, "us-east-1"), REGIONS)
    assert collected.errors == []

    resources = {r.resource_id: r for r in normalize_ec2(collected.raw)}
    assert seeded.instance_id in resources
    assert resources[seeded.instance_id].name == "bastion"

    group = resources[seeded.open_group_id].config
    assert isinstance(group, SecurityGroupConfig)
    assert seeded.instance_id in group.attached_instance_ids
    ssh = [p for p in group.inbound if p.from_port == 22]
    assert ssh and ssh[0].protocol == "tcp" and "0.0.0.0/0" in ssh[0].cidrs_v4


def test_s3_buckets_regions_encryption_and_public_access(policy_status: dict[str, bool]) -> None:
    seed_environment()
    policy_status["cs-public-bucket"] = True
    boto3.client("s3control", region_name="us-east-1").put_public_access_block(
        AccountId=MOTO_ACCOUNT_ID,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    collected = collect_s3(build_session(None, "us-east-1"), MOTO_ACCOUNT_ID)
    assert collected.errors == []
    buckets = {r.resource_id: r for r in normalize_s3(collected.raw)}
    assert {"cs-public-bucket", "cs-private-eu", "cs-audit-logs"} <= set(buckets)

    private = buckets["cs-private-eu"]
    assert private.region == "eu-west-1"
    private_config = private.config
    assert isinstance(private_config, S3BucketConfig)
    assert private_config.encryption_configured is True
    assert private_config.encryption_algorithm == "aws:kms"
    assert private_config.public_access_block is not None
    assert private_config.public_access_block.block_public_policy is True

    public_config = buckets["cs-public-bucket"].config
    assert isinstance(public_config, S3BucketConfig)
    assert buckets["cs-public-bucket"].region == "us-east-1"
    assert public_config.policy_is_public is True
    assert public_config.public_access_block is None
    assert public_config.account_public_access_block is not None
    assert public_config.account_public_access_block.block_public_policy is False
    assert public_config.unknown_checks == []


def test_iam_users_roles_mfa_and_broad_permissions() -> None:
    seed_environment()
    collected = collect_iam(build_session(None, "us-east-1"), sleep=lambda _: None)
    assert collected.errors == []

    resources = {r.name: r for r in normalize_iam(collected.raw)}
    alice = resources["alice"].config
    assert isinstance(alice, IamUserConfig)
    assert alice.password_enabled is True
    assert alice.mfa_active is False
    assert alice.permissions_analyzed is True
    assert [s.actions for s in alice.broad_statements] == [["*"]]

    bot = resources["readonly-bot"].config
    assert isinstance(bot, IamUserConfig)
    assert bot.broad_statements == []

    role = resources["ops-admin"].config
    assert isinstance(role, IamRoleConfig)
    assert role.uses_admin_managed_policy is True


def test_cloudtrail_multi_region_trail_is_found_once_and_logging() -> None:
    seeded = seed_environment()
    collected = collect_cloudtrail(build_session(None, "us-east-1"), REGIONS)
    assert collected.errors == []

    trails = normalize_cloudtrail(collected.raw)
    assert [t.resource_id for t in trails] == [seeded.trail_arn]
    config = trails[0].config
    assert isinstance(config, CloudTrailConfig)
    assert config.is_multi_region is True
    assert config.is_logging is True


def test_empty_account_collects_without_errors(policy_status: dict[str, bool]) -> None:
    session = build_session(None, "us-east-1")
    assert collect_s3(session, MOTO_ACCOUNT_ID).raw.buckets == []
    assert collect_cloudtrail(session, REGIONS).raw.trails == []
