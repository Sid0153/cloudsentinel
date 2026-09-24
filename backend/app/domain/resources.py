"""Plain, typed descriptions of AWS resources after normalization.

Nothing here knows about boto3, HTTP or the database. Collectors fetch raw AWS data,
normalizers turn it into these objects, and the rule engine reads them.
A value that could not be determined is None, never a guess.
"""

import enum
from dataclasses import asdict, dataclass, field
from typing import Any

GLOBAL_REGION = "global"
UNKNOWN_REGION = "unknown"


class ResourceType(enum.StrEnum):
    ACCOUNT = "AWS::Account"
    EC2_INSTANCE = "AWS::EC2::Instance"
    SECURITY_GROUP = "AWS::EC2::SecurityGroup"
    S3_BUCKET = "AWS::S3::Bucket"
    IAM_USER = "AWS::IAM::User"
    IAM_ROLE = "AWS::IAM::Role"
    CLOUDTRAIL_TRAIL = "AWS::CloudTrail::Trail"


@dataclass(frozen=True)
class AccountConfig:
    account_id: str
    caller_arn: str


@dataclass(frozen=True)
class Ec2InstanceConfig:
    state: str
    instance_type: str | None
    public_ip: str | None
    private_ip: str | None
    vpc_id: str | None
    subnet_id: str | None
    security_group_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class IpPermission:
    """One security group rule. protocol is "tcp", "udp", "icmp", "icmpv6" or "-1" (all)."""

    protocol: str
    from_port: int | None
    to_port: int | None
    cidrs_v4: list[str] = field(default_factory=list)
    cidrs_v6: list[str] = field(default_factory=list)
    source_security_groups: list[str] = field(default_factory=list)
    prefix_lists: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityGroupConfig:
    group_name: str
    description: str | None
    vpc_id: str | None
    inbound: list[IpPermission] = field(default_factory=list)
    outbound: list[IpPermission] = field(default_factory=list)
    # Only EC2 instances are checked. Groups used by load balancers, RDS or Lambda network
    # interfaces show no attachment here.
    attached_instance_ids: list[str] = field(default_factory=list)
    # False when the instance list for this region could not be read, so the attachment
    # list above is not reliable.
    attachments_known: bool = True


@dataclass(frozen=True)
class PublicAccessBlock:
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool


@dataclass(frozen=True)
class S3BucketConfig:
    encryption_configured: bool | None  # None: could not be checked
    encryption_algorithm: str | None  # "AES256", "aws:kms", "aws:kms:dsse"
    public_access_block: PublicAccessBlock | None  # None: no bucket-level block configured
    account_public_access_block: PublicAccessBlock | None
    policy_is_public: bool | None  # False when there is no policy; None: could not be checked
    acl_public_grants: list[str] = field(default_factory=list)  # e.g. "AllUsers:READ"
    # Checks that failed (for example access denied). Values for these are not reliable.
    unknown_checks: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BroadStatement:
    """An Allow statement with a wildcard action ("*" or "service:*") on Resource "*"."""

    source: str  # where it came from, e.g. "inline:Name" or "group:Admins/managed:<arn>"
    actions: list[str]
    resources: list[str]
    has_condition: bool


@dataclass(frozen=True)
class IamUserConfig:
    password_enabled: bool | None  # console password; None: credential report unavailable
    mfa_active: bool | None
    access_key_1_active: bool | None
    access_key_2_active: bool | None
    permissions_analyzed: bool  # False when the policy data could not be read
    groups: list[str] = field(default_factory=list)
    attached_policy_arns: list[str] = field(default_factory=list)
    broad_statements: list[BroadStatement] = field(default_factory=list)
    # AWS-managed AdministratorAccess attached directly or through a group.
    uses_admin_managed_policy: bool = False


@dataclass(frozen=True)
class IamRoleConfig:
    path: str
    attached_policy_arns: list[str] = field(default_factory=list)
    broad_statements: list[BroadStatement] = field(default_factory=list)
    uses_admin_managed_policy: bool = False


@dataclass(frozen=True)
class CloudTrailConfig:
    home_region: str
    is_multi_region: bool
    is_organization_trail: bool
    log_file_validation: bool
    s3_bucket: str | None
    is_logging: bool | None  # None: status could not be read


ResourceConfig = (
    AccountConfig
    | Ec2InstanceConfig
    | SecurityGroupConfig
    | S3BucketConfig
    | IamUserConfig
    | IamRoleConfig
    | CloudTrailConfig
)


@dataclass(frozen=True)
class NormalizedResource:
    resource_type: ResourceType
    resource_id: str  # AWS identifier: instance ID, group ID, bucket name or ARN
    region: str  # a region name, "global" or "unknown"
    name: str | None
    config: ResourceConfig

    def config_dict(self) -> dict[str, Any]:
        """JSON-friendly form of the configuration, as stored in the database."""
        return asdict(self.config)


ResourceKey = tuple[str, str, str]  # (region, resource_type, resource_id): unique per account


def resource_key(resource: NormalizedResource) -> ResourceKey:
    return (resource.region, str(resource.resource_type), resource.resource_id)
