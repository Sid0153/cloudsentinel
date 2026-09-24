"""Builders for normalized resources: secure by default, made vulnerable per test.

Each builder takes keyword overrides for the config, so a test states only what matters,
e.g. bucket(acl_public_grants=["AllUsers:READ"]).
"""

from dataclasses import replace
from typing import Any

from app.domain.coverage import Coverage, CoverageStatus
from app.domain.resources import (
    GLOBAL_REGION,
    AccountConfig,
    BroadStatement,
    CloudTrailConfig,
    Ec2InstanceConfig,
    IamRoleConfig,
    IamUserConfig,
    IpPermission,
    NormalizedResource,
    PublicAccessBlock,
    ResourceType,
    S3BucketConfig,
    SecurityGroupConfig,
)
from app.rules.model import RuleContext

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
ALL_BLOCKED = PublicAccessBlock(True, True, True, True)
NOTHING_BLOCKED = PublicAccessBlock(False, False, False, False)


def full_coverage() -> Coverage:
    return {
        service: {"status": CoverageStatus.SUCCEEDED, "items": 1, "error_count": 0, "errors": []}
        for service in ("ec2", "s3", "iam", "cloudtrail")
    }


def context(*resources: NormalizedResource, coverage: Coverage | None = None) -> RuleContext:
    return RuleContext(resources=list(resources), coverage=coverage or full_coverage())


def inbound(
    protocol: str = "tcp",
    from_port: int | None = 22,
    to_port: int | None = None,
    v4: list[str] | None = None,
    v6: list[str] | None = None,
    groups: list[str] | None = None,
) -> IpPermission:
    return IpPermission(
        protocol=protocol,
        from_port=from_port,
        to_port=from_port if to_port is None else to_port,
        cidrs_v4=v4 or [],
        cidrs_v6=v6 or [],
        source_security_groups=groups or [],
    )


def security_group(
    *rules: IpPermission, group_id: str = "sg-1", **overrides: Any
) -> NormalizedResource:
    config = SecurityGroupConfig(
        group_name="test",
        description=None,
        vpc_id="vpc-1",
        inbound=list(rules),
        attached_instance_ids=["i-1"],
    )
    return NormalizedResource(
        ResourceType.SECURITY_GROUP, group_id, REGION, "test", replace(config, **overrides)
    )


def instance(
    instance_id: str = "i-1", region: str = REGION, **overrides: Any
) -> NormalizedResource:
    config = Ec2InstanceConfig(
        state="running",
        instance_type="t3.micro",
        public_ip="203.0.113.5",
        private_ip="10.0.0.5",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        security_group_ids=["sg-1"],
    )
    return NormalizedResource(
        ResourceType.EC2_INSTANCE, instance_id, region, None, replace(config, **overrides)
    )


def bucket(name: str = "bucket", **overrides: Any) -> NormalizedResource:
    config = S3BucketConfig(
        encryption_configured=True,
        encryption_algorithm="AES256",
        public_access_block=None,
        account_public_access_block=None,
        policy_is_public=False,
    )
    return NormalizedResource(
        ResourceType.S3_BUCKET, name, REGION, name, replace(config, **overrides)
    )


def broad(actions: list[str] | None = None, condition: bool = False) -> BroadStatement:
    return BroadStatement(
        source="inline:test", actions=actions or ["*"], resources=["*"], has_condition=condition
    )


def iam_user(name: str = "alice", **overrides: Any) -> NormalizedResource:
    config = IamUserConfig(
        password_enabled=True,
        mfa_active=True,
        access_key_1_active=False,
        access_key_2_active=False,
        permissions_analyzed=True,
    )
    return NormalizedResource(
        ResourceType.IAM_USER,
        f"arn:aws:iam::{ACCOUNT_ID}:user/{name}",
        GLOBAL_REGION,
        name,
        replace(config, **overrides),
    )


def iam_role(name: str = "app", path: str = "/", **overrides: Any) -> NormalizedResource:
    config = IamRoleConfig(path=path)
    return NormalizedResource(
        ResourceType.IAM_ROLE,
        f"arn:aws:iam::{ACCOUNT_ID}:role{path}{name}",
        GLOBAL_REGION,
        name,
        replace(config, **overrides),
    )


def trail(name: str = "main", **overrides: Any) -> NormalizedResource:
    config = CloudTrailConfig(
        home_region=REGION,
        is_multi_region=True,
        is_organization_trail=False,
        log_file_validation=True,
        s3_bucket="logs",
        is_logging=True,
    )
    return NormalizedResource(
        ResourceType.CLOUDTRAIL_TRAIL,
        f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/{name}",
        REGION,
        name,
        replace(config, **overrides),
    )


def account() -> NormalizedResource:
    return NormalizedResource(
        ResourceType.ACCOUNT,
        ACCOUNT_ID,
        GLOBAL_REGION,
        None,
        AccountConfig(account_id=ACCOUNT_ID, caller_arn=f"arn:aws:iam::{ACCOUNT_ID}:user/scanner"),
    )
