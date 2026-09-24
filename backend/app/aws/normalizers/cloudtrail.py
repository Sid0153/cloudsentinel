from app.aws.raw import RawCloudTrail
from app.domain.resources import CloudTrailConfig, NormalizedResource, ResourceType


def normalize_cloudtrail(raw: RawCloudTrail) -> list[NormalizedResource]:
    resources: list[NormalizedResource] = []
    for trail in raw.trails:
        arn = str(trail["TrailARN"])
        home_region = str(trail.get("HomeRegion", "unknown"))
        resources.append(
            NormalizedResource(
                resource_type=ResourceType.CLOUDTRAIL_TRAIL,
                resource_id=arn,
                region=home_region,
                name=trail.get("Name"),
                config=CloudTrailConfig(
                    home_region=home_region,
                    is_multi_region=bool(trail.get("IsMultiRegionTrail", False)),
                    is_organization_trail=bool(trail.get("IsOrganizationTrail", False)),
                    log_file_validation=bool(trail.get("LogFileValidationEnabled", False)),
                    s3_bucket=trail.get("S3BucketName"),
                    is_logging=raw.is_logging.get(arn),
                ),
            )
        )
    return resources
