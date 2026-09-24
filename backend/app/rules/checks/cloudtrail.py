"""CloudTrail rule: is there a multi-region trail that is currently logging?

This is an account-wide question, so the rule is evaluated once, against the AWS::Account
resource, and reads the trails from the scan context. Event selectors, delivery health, KMS
encryption of logs and organization-level coverage are not checked.
"""

from typing import Any

from app.domain.resources import CloudTrailConfig, NormalizedResource, ResourceType
from app.rules.model import Outcome, RuleContext, Severity, check, config_of


def _trail(resource: NormalizedResource, config: CloudTrailConfig) -> dict[str, Any]:
    return {
        "name": resource.name,
        "home_region": config.home_region,
        "multi_region": config.is_multi_region,
        "logging": config.is_logging,
        "log_file_validation": config.log_file_validation,
    }


@check("CS-CT-001", ResourceType.ACCOUNT)
def no_multi_region_logging_trail(resource: NormalizedResource, context: RuleContext) -> Outcome:
    trails = [
        (trail, config_of(trail, CloudTrailConfig))
        for trail in context.of_type(ResourceType.CLOUDTRAIL_TRAIL)
    ]
    if any(config.is_multi_region and config.is_logging is True for _, config in trails):
        return Outcome.passed()  # one good trail is enough, even if some calls failed

    if any(config.is_multi_region and config.is_logging is None for _, config in trails):
        return Outcome.unknown("the logging status of a multi-region trail could not be read")
    if not context.fully_read(ResourceType.CLOUDTRAIL_TRAIL):
        return Outcome.unknown("not every region's trails could be read")

    some_logging = any(config.is_logging is True for _, config in trails)
    evidence = {
        "trail_count": len(trails),
        "trails": [_trail(trail, config) for trail, config in trails],
        "some_single_region_trail_logging": some_logging,
    }
    # No logging at all is worse than logging in some regions only.
    return Outcome.failed(evidence, severity=Severity.MEDIUM if some_logging else Severity.HIGH)
