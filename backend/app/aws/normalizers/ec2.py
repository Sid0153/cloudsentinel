from collections import defaultdict
from typing import Any

from app.aws.raw import RawEc2
from app.domain.resources import (
    Ec2InstanceConfig,
    IpPermission,
    NormalizedResource,
    ResourceType,
    SecurityGroupConfig,
)

# EC2 usually reports names, but numeric protocol values are valid too.
_PROTOCOL_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}


def _name_tag(tags: list[dict[str, Any]] | None) -> str | None:
    for tag in tags or []:
        if tag.get("Key") == "Name" and tag.get("Value"):
            return str(tag["Value"])
    return None


def _port(value: Any) -> int | None:
    return int(value) if isinstance(value, int) else None


def _permission(raw: dict[str, Any]) -> IpPermission:
    protocol = str(raw.get("IpProtocol", "-1")).lower()
    return IpPermission(
        protocol=_PROTOCOL_NAMES.get(protocol, protocol),
        from_port=_port(raw.get("FromPort")),
        to_port=_port(raw.get("ToPort")),
        cidrs_v4=[str(r["CidrIp"]) for r in raw.get("IpRanges", []) if "CidrIp" in r],
        cidrs_v6=[str(r["CidrIpv6"]) for r in raw.get("Ipv6Ranges", []) if "CidrIpv6" in r],
        source_security_groups=[
            str(p["GroupId"]) for p in raw.get("UserIdGroupPairs", []) if "GroupId" in p
        ],
        prefix_lists=[str(p["PrefixListId"]) for p in raw.get("PrefixListIds", [])],
    )


def normalize_ec2(raw: RawEc2) -> list[NormalizedResource]:
    resources: list[NormalizedResource] = []
    attached: dict[tuple[str, str], list[str]] = defaultdict(list)  # (region, group) -> ids

    for region, instance in raw.instances:
        state = str(instance.get("State", {}).get("Name", "unknown"))
        if state == "terminated":
            continue  # terminated instances linger in the API for about an hour
        instance_id = str(instance["InstanceId"])
        group_ids = [str(g["GroupId"]) for g in instance.get("SecurityGroups", [])]
        for group_id in group_ids:
            attached[(region, group_id)].append(instance_id)
        resources.append(
            NormalizedResource(
                resource_type=ResourceType.EC2_INSTANCE,
                resource_id=instance_id,
                region=region,
                name=_name_tag(instance.get("Tags")),
                config=Ec2InstanceConfig(
                    state=state,
                    instance_type=instance.get("InstanceType"),
                    public_ip=instance.get("PublicIpAddress"),
                    private_ip=instance.get("PrivateIpAddress"),
                    vpc_id=instance.get("VpcId"),
                    subnet_id=instance.get("SubnetId"),
                    security_group_ids=group_ids,
                ),
            )
        )

    for region, group in raw.security_groups:
        group_id = str(group["GroupId"])
        resources.append(
            NormalizedResource(
                resource_type=ResourceType.SECURITY_GROUP,
                resource_id=group_id,
                region=region,
                name=str(group.get("GroupName", group_id)),
                config=SecurityGroupConfig(
                    group_name=str(group.get("GroupName", "")),
                    description=group.get("Description"),
                    vpc_id=group.get("VpcId"),
                    inbound=[_permission(p) for p in group.get("IpPermissions", [])],
                    outbound=[_permission(p) for p in group.get("IpPermissionsEgress", [])],
                    attached_instance_ids=sorted(attached.get((region, group_id), [])),
                    attachments_known=region not in raw.instance_regions_failed,
                ),
            )
        )
    return resources
