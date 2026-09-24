from app.aws.normalizers.cloudtrail import normalize_cloudtrail
from app.aws.raw import RawCloudTrail
from app.domain.resources import CloudTrailConfig, ResourceType
from tests.fixtures.aws_raw import MULTI_REGION_TRAIL


def test_trail_is_normalized_with_logging_status() -> None:
    raw = RawCloudTrail(
        trails=[MULTI_REGION_TRAIL], is_logging={MULTI_REGION_TRAIL["TrailARN"]: True}
    )
    [trail] = normalize_cloudtrail(raw)
    assert trail.resource_type is ResourceType.CLOUDTRAIL_TRAIL
    assert trail.region == "us-east-1"
    config = trail.config
    assert isinstance(config, CloudTrailConfig)
    assert config.is_multi_region is True
    assert config.log_file_validation is True
    assert config.is_logging is True


def test_unreadable_status_is_unknown() -> None:
    [trail] = normalize_cloudtrail(RawCloudTrail(trails=[MULTI_REGION_TRAIL]))
    config = trail.config
    assert isinstance(config, CloudTrailConfig)
    assert config.is_logging is None


def test_no_trails() -> None:
    assert normalize_cloudtrail(RawCloudTrail()) == []
