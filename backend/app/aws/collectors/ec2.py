"""EC2 instances and security groups, per region."""

from app.aws.common import AWS_ERRORS, BOTO_CONFIG, Boto3Session, Collected, error_label
from app.aws.raw import RawEc2


def collect_ec2(session: Boto3Session, regions: list[str]) -> Collected[RawEc2]:
    result = Collected(raw=RawEc2())
    for region in regions:
        client = session.client("ec2", region_name=region, config=BOTO_CONFIG)

        try:
            for page in client.get_paginator("describe_instances").paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        result.raw.instances.append((region, instance))
        except AWS_ERRORS as exc:
            result.raw.instance_regions_failed.add(region)
            result.errors.append(f"{region}: {error_label('DescribeInstances', exc)}")

        try:
            for page in client.get_paginator("describe_security_groups").paginate():
                for group in page.get("SecurityGroups", []):
                    result.raw.security_groups.append((region, group))
        except AWS_ERRORS as exc:
            result.errors.append(f"{region}: {error_label('DescribeSecurityGroups', exc)}")

    result.items = len(result.raw.instances) + len(result.raw.security_groups)
    return result
