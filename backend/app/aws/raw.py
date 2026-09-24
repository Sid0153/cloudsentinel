"""Raw AWS data as collected, before normalization. Plain data only, no boto3."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CallerIdentity:
    account_id: str
    arn: str


@dataclass
class RawEc2:
    instances: list[tuple[str, dict[str, Any]]] = field(default_factory=list)  # (region, data)
    security_groups: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    instance_regions_failed: set[str] = field(default_factory=set)


@dataclass
class RawBucket:
    name: str
    region: str
    encryption_rules: list[dict[str, Any]] | None  # None: no default encryption configured
    public_access_block: dict[str, Any] | None  # None: none configured
    policy_is_public: bool | None  # False: no bucket policy; None: unknown
    acl_grants: list[dict[str, Any]] = field(default_factory=list)
    unknown_checks: list[str] = field(default_factory=list)


@dataclass
class RawS3:
    buckets: list[RawBucket] = field(default_factory=list)
    account_public_access_block: dict[str, Any] | None = None
    account_public_access_block_unknown: bool = False


@dataclass
class RawIam:
    credential_report: list[dict[str, str]] | None = None  # None: could not be read
    authorization_details: dict[str, list[dict[str, Any]]] | None = None  # None: not read


@dataclass
class RawCloudTrail:
    trails: list[dict[str, Any]] = field(default_factory=list)
    is_logging: dict[str, bool | None] = field(default_factory=dict)  # keyed by trail ARN
