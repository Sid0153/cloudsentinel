"""CloudTrail trails and whether they are currently logging.

Each scanned region is asked for its trails including "shadow" copies of multi-region
trails homed elsewhere, then results are de-duplicated by ARN. Event selectors and
delivery health are not checked.
"""

from typing import Any

from app.aws.common import AWS_ERRORS, BOTO_CONFIG, Boto3Session, Collected, error_label
from app.aws.raw import RawCloudTrail


def collect_cloudtrail(session: Boto3Session, regions: list[str]) -> Collected[RawCloudTrail]:
    result = Collected(raw=RawCloudTrail())
    clients: dict[str, Any] = {}

    def client_for(region: str) -> Any:
        if region not in clients:
            clients[region] = session.client("cloudtrail", region_name=region, config=BOTO_CONFIG)
        return clients[region]

    trails_by_arn: dict[str, dict[str, Any]] = {}
    for region in regions:
        try:
            response = client_for(region).describe_trails(includeShadowTrails=True)
        except AWS_ERRORS as exc:
            result.errors.append(f"{region}: {error_label('DescribeTrails', exc)}")
            continue
        for trail in response.get("trailList", []):
            arn = trail.get("TrailARN")
            if arn:
                trails_by_arn.setdefault(str(arn), trail)

    for arn, trail in trails_by_arn.items():
        home_region = str(trail.get("HomeRegion") or regions[0])
        try:
            status = client_for(home_region).get_trail_status(Name=arn)
            is_logging = status.get("IsLogging")
            result.raw.is_logging[arn] = is_logging if isinstance(is_logging, bool) else None
        except AWS_ERRORS as exc:
            result.raw.is_logging[arn] = None
            label = error_label("GetTrailStatus", exc)
            result.errors.append(f"{trail.get('Name', 'trail')}: {label}")
        result.raw.trails.append(trail)

    result.items = len(result.raw.trails)
    return result
