from app.aws.normalizers.ec2 import normalize_ec2
from app.aws.raw import RawEc2
from app.domain.resources import NormalizedResource, ResourceType, SecurityGroupConfig
from tests.fixtures.aws_raw import (
    OPEN_SSH_GROUP,
    PRIVATE_GROUP,
    REGION,
    RUNNING_INSTANCE,
    TERMINATED_INSTANCE,
)


def _by_id(resources: list[NormalizedResource]) -> dict[str, NormalizedResource]:
    return {r.resource_id: r for r in resources}


def _raw(failed: set[str] | None = None) -> RawEc2:
    return RawEc2(
        instances=[(REGION, RUNNING_INSTANCE), (REGION, TERMINATED_INSTANCE)],
        security_groups=[(REGION, OPEN_SSH_GROUP), (REGION, PRIVATE_GROUP)],
        instance_regions_failed=failed or set(),
    )


def test_running_instance_is_normalized_with_name_tag() -> None:
    instance = _by_id(normalize_ec2(_raw()))["i-running"]
    assert instance.resource_type is ResourceType.EC2_INSTANCE
    assert instance.name == "bastion"
    config = instance.config_dict()
    assert config["state"] == "running"
    assert config["public_ip"] == "203.0.113.10"
    assert config["security_group_ids"] == ["sg-open"]


def test_terminated_instances_are_skipped_and_do_not_count_as_attachments() -> None:
    resources = _by_id(normalize_ec2(_raw()))
    assert "i-gone" not in resources
    private = resources["sg-private"].config
    assert isinstance(private, SecurityGroupConfig)
    assert private.attached_instance_ids == []


def test_security_group_rules_keep_protocol_ports_and_sources() -> None:
    group = _by_id(normalize_ec2(_raw()))["sg-open"].config
    assert isinstance(group, SecurityGroupConfig)
    assert group.attached_instance_ids == ["i-running"]
    rule = group.inbound[0]
    assert (rule.protocol, rule.from_port, rule.to_port) == ("tcp", 22, 22)
    assert rule.cidrs_v4 == ["0.0.0.0/0"]
    assert rule.cidrs_v6 == ["::/0"]

    egress = group.outbound[0]
    assert egress.protocol == "-1"
    assert (egress.from_port, egress.to_port) == (None, None)


def test_numeric_protocol_and_group_and_prefix_list_sources() -> None:
    group = _by_id(normalize_ec2(_raw()))["sg-private"].config
    assert isinstance(group, SecurityGroupConfig)
    rule = group.inbound[0]
    assert rule.protocol == "tcp"
    assert rule.cidrs_v4 == []
    assert rule.source_security_groups == ["sg-open"]
    assert rule.prefix_lists == ["pl-123"]


def test_attachments_are_marked_unknown_when_instances_could_not_be_listed() -> None:
    group = _by_id(normalize_ec2(_raw(failed={REGION})))["sg-open"].config
    assert isinstance(group, SecurityGroupConfig)
    assert group.attachments_known is False


def test_empty_input_gives_no_resources() -> None:
    assert normalize_ec2(RawEc2()) == []
