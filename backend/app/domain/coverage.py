"""How completely each AWS service was read during a scan.

Discovery writes one coverage entry per service; the rule engine and the findings sync read
it to decide whether "nothing found" can be trusted.
"""

from typing import Any

from app.domain.resources import ResourceType


class CoverageStatus:
    SUCCEEDED = "SUCCEEDED"  # everything was read
    PARTIAL = "PARTIAL"  # some calls failed; results for this service are incomplete
    FAILED = "FAILED"  # nothing usable was read for this service


# The discovery service that produces each resource type. The account comes from STS, which
# must succeed for a scan to run at all, so it has no entry.
SERVICE_FOR_TYPE: dict[ResourceType, str] = {
    ResourceType.EC2_INSTANCE: "ec2",
    ResourceType.SECURITY_GROUP: "ec2",
    ResourceType.S3_BUCKET: "s3",
    ResourceType.IAM_USER: "iam",
    ResourceType.IAM_ROLE: "iam",
    ResourceType.CLOUDTRAIL_TRAIL: "cloudtrail",
}

Coverage = dict[str, dict[str, Any]]  # service name -> {"status": ..., "items": ..., ...}


def type_fully_read(coverage: Coverage, resource_type: ResourceType) -> bool:
    """True when every resource of this type in the scanned scope was read without errors."""
    service = SERVICE_FOR_TYPE.get(resource_type)
    if service is None:
        return True
    return coverage.get(service, {}).get("status") == CoverageStatus.SUCCEEDED
