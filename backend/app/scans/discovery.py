"""Runs every collector and normalizer for one account. Talks to AWS; never to the database."""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.aws.collectors.cloudtrail import collect_cloudtrail
from app.aws.collectors.ec2 import collect_ec2
from app.aws.collectors.iam import collect_iam
from app.aws.collectors.s3 import collect_s3
from app.aws.common import Boto3Session, Collected
from app.aws.normalizers.cloudtrail import normalize_cloudtrail
from app.aws.normalizers.ec2 import normalize_ec2
from app.aws.normalizers.iam import normalize_iam
from app.aws.normalizers.s3 import normalize_s3
from app.aws.raw import CallerIdentity
from app.domain.resources import GLOBAL_REGION, AccountConfig, NormalizedResource, ResourceType

logger = logging.getLogger(__name__)

MAX_ERRORS_PER_SERVICE = 20


class CoverageStatus:
    SUCCEEDED = "SUCCEEDED"  # everything was read
    PARTIAL = "PARTIAL"  # some calls failed; results for this service are incomplete
    FAILED = "FAILED"  # nothing usable was read for this service


@dataclass
class Discovery:
    resources: list[NormalizedResource] = field(default_factory=list)
    coverage: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return all(entry["status"] == CoverageStatus.SUCCEEDED for entry in self.coverage.values())


def coverage_entry(collected: Collected[Any]) -> dict[str, Any]:
    if not collected.errors:
        status = CoverageStatus.SUCCEEDED
    elif collected.items > 0:
        status = CoverageStatus.PARTIAL
    else:
        status = CoverageStatus.FAILED
    return {
        "status": status,
        "items": collected.items,
        "error_count": len(collected.errors),
        "errors": collected.errors[:MAX_ERRORS_PER_SERVICE],
    }


def account_resource(identity: CallerIdentity) -> NormalizedResource:
    return NormalizedResource(
        resource_type=ResourceType.ACCOUNT,
        resource_id=identity.account_id,
        region=GLOBAL_REGION,
        name=None,
        config=AccountConfig(account_id=identity.account_id, caller_arn=identity.arn),
    )


def discover(
    session: Boto3Session, identity: CallerIdentity, regions: list[str]
) -> Discovery:
    discovery = Discovery(resources=[account_resource(identity)])

    def ec2() -> tuple[Collected[Any], list[NormalizedResource]]:
        collected = collect_ec2(session, regions)
        return collected, normalize_ec2(collected.raw)

    def s3() -> tuple[Collected[Any], list[NormalizedResource]]:
        collected = collect_s3(session, identity.account_id)
        return collected, normalize_s3(collected.raw)

    def iam() -> tuple[Collected[Any], list[NormalizedResource]]:
        collected = collect_iam(session)
        return collected, normalize_iam(collected.raw)

    def cloudtrail() -> tuple[Collected[Any], list[NormalizedResource]]:
        collected = collect_cloudtrail(session, regions)
        return collected, normalize_cloudtrail(collected.raw)

    services: dict[str, Callable[[], tuple[Collected[Any], list[NormalizedResource]]]] = {
        "ec2": ec2,
        "s3": s3,
        "iam": iam,
        "cloudtrail": cloudtrail,
    }

    for name, run in services.items():
        # One service failing (even from a bug) must not lose the results of the others.
        try:
            collected, resources = run()
        except Exception:
            logger.exception("Unexpected error while scanning %s", name)
            discovery.coverage[name] = {
                "status": CoverageStatus.FAILED,
                "items": 0,
                "error_count": 1,
                "errors": ["Internal error while processing this service"],
            }
            continue
        discovery.resources.extend(resources)
        discovery.coverage[name] = coverage_entry(collected)
    return discovery
